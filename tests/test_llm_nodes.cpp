#include <gtest/gtest.h>
#include "domains/graph/engine/graph_runner.h"
#include "domains/graph/engine/task_graph.h"
#include "domains/graph/nodes/code_node.h"
#include "domains/graph/nodes/llm_call_node.h"
#include "domains/graph/nodes/supervised_llm_call_node.h"
#include "infra/llm/LLMBackend.h"

using namespace area::graph;

TEST(TemplateResolver, ResolvesVariables) {
    TaskContext ctx;
    ctx.set("name", "sendSMS");
    ctx.set("body", "invoke-static SmsManager");

    auto result = resolveTemplate("Method: {{name}}\nBody: {{body}}", ctx);
    EXPECT_EQ(result, "Method: sendSMS\nBody: invoke-static SmsManager");
}

TEST(TemplateResolver, LeavesUnresolvedVars) {
    TaskContext ctx;
    ctx.set("name", "test");

    auto result = resolveTemplate("{{name}} and {{missing}}", ctx);
    EXPECT_EQ(result, "test and {{missing}}");
}

TEST(TemplateResolver, ResolvesJsonValues) {
    TaskContext ctx;
    ctx.set("data", nlohmann::json::array({1, 2, 3}));

    auto result = resolveTemplate("Data: {{data}}", ctx);
    EXPECT_EQ(result, "Data: [1,2,3]");
}

TEST(TemplateResolver, NoPlaceholders) {
    TaskContext ctx;
    auto result = resolveTemplate("just plain text", ctx);
    EXPECT_EQ(result, "just plain text");
}

TEST(LLMCallNode, CallsMockBackend) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    area::MockBackend mock(ep);
    mock.setResponse(R"({"relevant": true, "confidence": 0.95, "findings": ["test"], "reasoning": "test"})");

    TaskGraph g("llm_test");
    auto llm = g.add<LLMCallNode>("call_llm",
        LLMCallConfig{.tier = 0, .prompt_template = "Analyze: {{code}}"},
        &mock);
    g.setEntry(llm);

    TaskContext ctx;
    ctx.set("code", "invoke-static SmsManager");

    GraphRunner runner;
    auto result = runner.run(g, std::move(ctx));

    EXPECT_TRUE(result.has("llm_response"));
    EXPECT_NE(result.get("llm_response").get<std::string>().find("relevant"), std::string::npos);
    EXPECT_TRUE(result.has("llm_prompt"));
    EXPECT_EQ(mock.callCount(), 1);
    EXPECT_NE(mock.lastUserMessage().content.find("SmsManager"), std::string::npos);
}

TEST(SupervisedLLMCallNode, PassesOnFirstTry) {
    area::AiEndpoint ep1{"worker", "mock", "", "auto"};
    area::AiEndpoint ep2{"supervisor", "mock", "", "auto"};
    area::MockBackend worker(ep1);
    area::MockBackend supervisor(ep2);

    worker.setResponse(R"({"relevant": true, "confidence": 0.7, "findings": ["test"], "reasoning": "test"})");
    supervisor.setResponse("PASS - output looks correct");

    TaskGraph g("supervised_test");
    auto node = g.add<SupervisedLLMCallNode>("supervised",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = "Analyze: {{code}}",
            .supervisor_prompt = "Check the output",
            .max_retries = 3,
        },
        &worker, &supervisor,
        [](const std::string& resp, const TaskContext&) {
            return resp.find("relevant") != std::string::npos;
        });
    g.setEntry(node);

    TaskContext ctx;
    ctx.set("code", "some smali");
    GraphRunner runner;
    auto result = runner.run(g, std::move(ctx));

    EXPECT_TRUE(result.has("llm_response"));
    EXPECT_TRUE(result.has("supervisor_verdict"));
    EXPECT_FALSE(result.has("llm_error"));
    EXPECT_EQ(worker.callCount(), 1);
    EXPECT_EQ(supervisor.callCount(), 1);
}

TEST(SupervisedLLMCallNode, RetriesOnSupervisorReject) {
    area::AiEndpoint ep1{"worker", "mock", "", "auto"};
    area::AiEndpoint ep2{"supervisor", "mock", "", "auto"};
    area::MockBackend worker(ep1);
    area::MockBackend supervisor(ep2);

    worker.setResponse(R"({"relevant": true, "confidence": 0.7, "findings": ["test"], "reasoning": "test"})");
    // Supervisor rejects first two, then passes
    supervisor.setResponses({
        "FAIL - missing confidence field",
        "FAIL - still missing fields",
        "PASS - looks good now"
    });

    TaskGraph g("retry_test");
    auto node = g.add<SupervisedLLMCallNode>("supervised",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = "Analyze: {{code}}",
            .supervisor_prompt = "Check output",
            .max_retries = 3,
        },
        &worker, &supervisor,
        nullptr); // no code validation, supervisor only
    g.setEntry(node);

    TaskContext ctx;
    ctx.set("code", "smali");
    GraphRunner runner;
    auto result = runner.run(g, std::move(ctx));

    EXPECT_TRUE(result.has("llm_response"));
    EXPECT_FALSE(result.has("llm_error"));
    // Worker called 3 times, supervisor called 3 times
    EXPECT_EQ(worker.callCount(), 3);
    EXPECT_EQ(supervisor.callCount(), 3);
}

TEST(SupervisedLLMCallNode, ExhaustsRetries) {
    area::AiEndpoint ep1{"worker", "mock", "", "auto"};
    area::AiEndpoint ep2{"supervisor", "mock", "", "auto"};
    area::MockBackend worker(ep1);
    area::MockBackend supervisor(ep2);

    worker.setResponse("not json at all");
    supervisor.setResponse("PASS");

    TaskGraph g("exhaust_test");
    auto node = g.add<SupervisedLLMCallNode>("supervised",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = "Analyze",
            .supervisor_prompt = "Check",
            .max_retries = 2,
        },
        &worker, &supervisor,
        [](const std::string& resp, const TaskContext&) {
            // Validation always fails (not valid JSON)
            try { auto j = nlohmann::json::parse(resp); (void)j; return true; } catch (...) { return false; }
        });
    g.setEntry(node);

    GraphRunner runner;
    auto result = runner.run(g, TaskContext{});

    // Should have llm_error after exhausting retries
    EXPECT_TRUE(result.has("llm_error"));
    // 3 attempts total (initial + 2 retries)
    EXPECT_EQ(worker.callCount(), 3);
}

TEST(TemplateResolver, EmptyTemplate) {
    TaskContext ctx;
    ctx.set("x", "ignored");
    EXPECT_EQ(resolveTemplate("", ctx), "");
}

TEST(TemplateResolver, AdjacentPlaceholders) {
    TaskContext ctx;
    ctx.set("a", "hello");
    ctx.set("b", "world");
    EXPECT_EQ(resolveTemplate("{{a}}{{b}}", ctx), "helloworld");
}

TEST(TemplateResolver, RepeatedVariable) {
    TaskContext ctx;
    ctx.set("x", "AB");
    EXPECT_EQ(resolveTemplate("{{x}}-{{x}}-{{x}}", ctx), "AB-AB-AB");
}

TEST(LLMCallNode, InGraphChain) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    area::MockBackend mock(ep);
    mock.setResponse(R"({"risk": "high"})");

    TaskGraph g("chain");

    auto prep = g.add<CodeNode>("prep", [](TaskContext ctx) {
        ctx.set("method", "sendSMS");
        return ctx;
    });
    auto llm = g.add<LLMCallNode>("analyze",
        LLMCallConfig{.prompt_template = "Analyze method {{method}}"},
        &mock);
    auto post = g.add<CodeNode>("post", [](TaskContext ctx) {
        auto resp = ctx.get("llm_response").get<std::string>();
        auto j = nlohmann::json::parse(resp);
        ctx.set("final_risk", j["risk"]);
        return ctx;
    });

    g.edge(prep, llm);
    g.edge(llm, post);
    g.setEntry(prep);
    g.setOutput(post);

    GraphRunner runner;
    auto result = runner.run(g, TaskContext{});

    EXPECT_EQ(result.get("final_risk"), "high");
}

TEST(SupervisedLLMCallNode, SkipsSupervisorWhenSameBackend) {
    area::AiEndpoint ep{"shared", "mock", "", "auto"};
    area::MockBackend backend(ep);
    backend.setResponse(R"({"ok": true})");

    TaskGraph g("same_backend");
    auto node = g.add<SupervisedLLMCallNode>("supervised",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = "Analyze",
            .supervisor_prompt = "Check",
        },
        &backend, &backend); // same pointer for worker and supervisor
    g.setEntry(node);

    GraphRunner runner;
    auto result = runner.run(g, TaskContext{});

    EXPECT_TRUE(result.has("llm_response"));
    EXPECT_FALSE(result.has("llm_error"));
    // Only 1 call — supervisor was skipped
    EXPECT_EQ(backend.callCount(), 1);
}

TEST(SupervisedLLMCallNode, ValidationFailsAllRetries) {
    area::AiEndpoint ep1{"worker", "mock", "", "auto"};
    area::AiEndpoint ep2{"supervisor", "mock", "", "auto"};
    area::MockBackend worker(ep1);
    area::MockBackend supervisor(ep2);

    worker.setResponse("bad output");
    supervisor.setResponse("PASS");

    TaskGraph g("val_fail");
    auto node = g.add<SupervisedLLMCallNode>("supervised",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = "Analyze",
            .supervisor_prompt = "Check",
            .max_retries = 1,
        },
        &worker, &supervisor,
        [](const std::string&, const TaskContext&) { return false; }); // always fails
    g.setEntry(node);

    GraphRunner runner;
    auto result = runner.run(g, TaskContext{});

    EXPECT_TRUE(result.has("llm_error"));
    EXPECT_EQ(worker.callCount(), 2); // initial + 1 retry
    EXPECT_EQ(supervisor.callCount(), 0); // never reached supervisor
}

#include "domains/graph/graphs/scan_task_graph.h"

TEST(TierBackends, ExactTierMatch) {
    area::AiEndpoint ep0{"t0", "mock", "", "auto"};
    area::AiEndpoint ep1{"t1", "mock", "", "auto"};
    area::MockBackend b0(ep0);
    area::MockBackend b1(ep1);

    TierBackends tb;
    tb.backends[0] = &b0;
    tb.backends[1] = &b1;

    EXPECT_EQ(tb.at(0), &b0);
    EXPECT_EQ(tb.at(1), &b1);
}

TEST(TierBackends, FallsBackToNearestTier) {
    area::AiEndpoint ep{"t1", "mock", "", "auto"};
    area::MockBackend b1(ep);

    TierBackends tb;
    tb.backends[1] = &b1;

    // Tier 0 and 2 both at distance 1 from tier 1 — should return b1
    EXPECT_EQ(tb.at(0), &b1);
    EXPECT_EQ(tb.at(2), &b1);
    EXPECT_EQ(tb.at(5), &b1);
}

TEST(TierBackends, ThrowsWhenEmpty) {
    TierBackends tb;
    EXPECT_THROW(tb.at(0), std::runtime_error);
}
