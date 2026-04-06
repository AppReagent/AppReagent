#include <gtest/gtest.h>
#include "graph/engine/graph_runner.h"
#include "graph/engine/task_graph.h"
#include "graph/nodes/code_node.h"
#include "graph/nodes/llm_call_node.h"
#include "graph/nodes/supervised_llm_call_node.h"
#include "LLMBackend.h"

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
