#include <gtest/gtest.h>
#include "graph/engine/task_context.h"
#include "graph/engine/task_graph.h"
#include "graph/engine/graph_runner.h"
#include "graph/nodes/code_node.h"
#include "graph/nodes/splitter_node.h"

using namespace area::graph;

TEST(TaskContext, SetGetHas) {
    TaskContext ctx;
    EXPECT_FALSE(ctx.has("key"));
    ctx.set("key", 42);
    EXPECT_TRUE(ctx.has("key"));
    EXPECT_EQ(ctx.get("key"), 42);
}

TEST(TaskContext, Merge) {
    TaskContext a, b;
    a.set("x", 1);
    a.set("shared", "from_a");
    b.set("y", 2);
    b.set("shared", "from_b");
    a.merge(b);
    EXPECT_EQ(a.get("x"), 1);
    EXPECT_EQ(a.get("y"), 2);
    EXPECT_EQ(a.get("shared"), "from_b"); // b wins
}

TEST(TaskContext, Metadata) {
    TaskContext ctx;
    ctx.task_id = "task-1";
    ctx.parent_task_id = "parent-1";
    ctx.error_count = 3;
    ctx.discarded = true;
    ctx.discard_reason = "benign";
    EXPECT_EQ(ctx.task_id, "task-1");
    EXPECT_TRUE(ctx.discarded);
}

TEST(GraphRunner, LinearGraph) {
    TaskGraph g("linear");

    auto a = g.add<CodeNode>("a", [](TaskContext ctx) {
        ctx.set("step", "a");
        return ctx;
    });
    auto b = g.add<CodeNode>("b", [](TaskContext ctx) {
        ctx.set("step", ctx.get("step").get<std::string>() + "->b");
        return ctx;
    });
    auto c = g.add<CodeNode>("c", [](TaskContext ctx) {
        ctx.set("step", ctx.get("step").get<std::string>() + "->c");
        return ctx;
    });

    g.edge(a, b);
    g.edge(b, c);
    g.setEntry(a);
    g.setOutput(c);

    GraphRunner runner;
    auto result = runner.run(g, TaskContext{});

    EXPECT_EQ(result.get("step"), "a->b->c");
}

TEST(GraphRunner, DecisionBranching) {
    TaskGraph g("decision");

    auto decide = g.add<DecisionCodeNode>("decide", [](const TaskContext& ctx) {
        return ctx.get("type").get<std::string>();
    });
    auto smali = g.add<CodeNode>("smali_handler", [](TaskContext ctx) {
        ctx.set("result", "handled_smali");
        return ctx;
    });
    auto elf = g.add<CodeNode>("elf_handler", [](TaskContext ctx) {
        ctx.set("result", "handled_elf");
        return ctx;
    });

    g.branch(decide, "smali", smali);
    g.branch(decide, "elf", elf);
    g.setEntry(decide);

    GraphRunner runner;

    // Test smali branch
    TaskContext ctx1;
    ctx1.set("type", "smali");
    auto r1 = runner.run(g, std::move(ctx1));
    EXPECT_EQ(r1.get("result"), "handled_smali");

    // Test elf branch
    TaskContext ctx2;
    ctx2.set("type", "elf");
    auto r2 = runner.run(g, std::move(ctx2));
    EXPECT_EQ(r2.get("result"), "handled_elf");
}

TEST(GraphRunner, PredicateRouting) {
    TaskGraph g("predicate");

    auto check = g.add<PredicateCodeNode>("check", [](const TaskContext& ctx) {
        return ctx.get("score").get<int>() > 50;
    });
    auto pass_node = g.add<CodeNode>("pass", [](TaskContext ctx) {
        ctx.set("verdict", "suspicious");
        return ctx;
    });
    auto fail_node = g.add<CodeNode>("fail", [](TaskContext ctx) {
        ctx.set("verdict", "benign");
        return ctx;
    });

    g.branch(check, "pass", pass_node);
    g.branch(check, "fail", fail_node);
    g.setEntry(check);

    GraphRunner runner;

    TaskContext high;
    high.set("score", 80);
    auto r1 = runner.run(g, std::move(high));
    EXPECT_EQ(r1.get("verdict"), "suspicious");

    TaskContext low;
    low.set("score", 20);
    auto r2 = runner.run(g, std::move(low));
    EXPECT_EQ(r2.get("verdict"), "benign");
}

TEST(GraphRunner, ExitNode) {
    TaskGraph g("exit");

    auto check = g.add<PredicateCodeNode>("check", [](const TaskContext& ctx) {
        return ctx.get("interesting").get<bool>();
    });
    auto proceed = g.add<CodeNode>("proceed", [](TaskContext ctx) {
        ctx.set("analyzed", true);
        return ctx;
    });
    auto exit = g.add<ExitNode>("exit", [](TaskContext& ctx) {
        ctx.discard_reason = "not_interesting";
    });

    g.branch(check, "pass", proceed);
    g.branch(check, "fail", exit);
    g.setEntry(check);

    GraphRunner runner;

    TaskContext boring;
    boring.set("interesting", false);
    auto r = runner.run(g, std::move(boring));
    EXPECT_TRUE(r.discarded);
}

TEST(GraphRunner, SplitterCollector) {
    TaskGraph g("fanout");

    auto splitter = g.add<SplitterNode>("split", [](TaskContext ctx) {
        std::vector<TaskContext> items;
        auto methods = ctx.get("methods");
        for (auto& m : methods) {
            TaskContext item;
            item.set("method", m);
            items.push_back(std::move(item));
        }
        return items;
    });

    auto analyze = g.add<CodeNode>("analyze", [](TaskContext ctx) {
        auto method = ctx.get("method").get<std::string>();
        ctx.set("risk", method == "sendSMS" ? "high" : "low");
        return ctx;
    });

    auto collector = g.add<CollectorNode>("collect");

    auto summarize = g.add<CodeNode>("summarize", [](TaskContext ctx) {
        auto collected = ctx.get("collected");
        int high_risk_count = 0;
        for (auto& item : collected) {
            if (item["risk"] == "high") high_risk_count++;
        }
        ctx.set("high_risk_count", high_risk_count);
        return ctx;
    });

    g.edge(splitter, analyze);
    g.branch(splitter, "collect", collector);
    g.edge(collector, summarize);
    g.setEntry(splitter);
    g.setOutput(summarize);

    GraphRunner runner;
    TaskContext initial;
    initial.set("methods", nlohmann::json::array({"onCreate", "sendSMS", "onDestroy"}));
    auto result = runner.run(g, std::move(initial));

    EXPECT_EQ(result.get("high_risk_count"), 1);
}

TEST(GraphRunner, SplitterWithEarlyExit) {
    TaskGraph g("fanout_exit");

    auto splitter = g.add<SplitterNode>("split", [](TaskContext ctx) {
        std::vector<TaskContext> items;
        for (auto& v : ctx.get("values")) {
            TaskContext item;
            item.set("value", v);
            items.push_back(std::move(item));
        }
        return items;
    });

    auto filter = g.add<PredicateCodeNode>("filter", [](const TaskContext& ctx) {
        return ctx.get("value").get<int>() > 5;
    });

    auto process = g.add<CodeNode>("process", [](TaskContext ctx) {
        ctx.set("processed", true);
        return ctx;
    });

    auto discard = g.add<ExitNode>("discard");

    auto collector = g.add<CollectorNode>("collect");

    g.edge(splitter, filter);
    g.branch(filter, "pass", process);
    g.branch(filter, "fail", discard);
    g.branch(splitter, "collect", collector);
    g.setEntry(splitter);
    g.setOutput(collector);

    GraphRunner runner;
    TaskContext initial;
    initial.set("values", nlohmann::json::array({1, 10, 3, 20, 2}));
    auto result = runner.run(g, std::move(initial));

    // Only values > 5 should be collected (10, 20)
    auto collected = result.get("collected");
    EXPECT_EQ(collected.size(), 2);
}

TEST(GraphRunner, ObservabilityCallbacks) {
    TaskGraph g("observable");

    auto a = g.add<CodeNode>("a", [](TaskContext ctx) { return ctx; });
    auto b = g.add<CodeNode>("b", [](TaskContext ctx) { return ctx; });
    g.edge(a, b);
    g.setEntry(a);

    std::vector<std::string> started, ended;
    GraphRunner runner;
    runner.onNodeStart([&](const std::string& name, const TaskContext&) { started.push_back(name); });
    runner.onNodeEnd([&](const std::string& name, const TaskContext&) { ended.push_back(name); });

    runner.run(g, TaskContext{});

    ASSERT_EQ(started.size(), 2);
    EXPECT_EQ(started[0], "a");
    EXPECT_EQ(started[1], "b");
    ASSERT_EQ(ended.size(), 2);
}

TEST(TaskGraph, DuplicateNodeThrows) {
    TaskGraph g("dup");
    g.add<CodeNode>("same_name", [](TaskContext ctx) { return ctx; });
    EXPECT_THROW(
        g.add<CodeNode>("same_name", [](TaskContext ctx) { return ctx; }),
        std::runtime_error
    );
}

TEST(GraphRunner, MissingEntryThrows) {
    TaskGraph g("empty");
    GraphRunner runner;
    EXPECT_THROW(runner.run(g, TaskContext{}), std::runtime_error);
}

// --- TaskContext additional tests ---

TEST(TaskContext, Remove) {
    TaskContext ctx;
    ctx.set("a", 1);
    ctx.set("b", 2);
    EXPECT_TRUE(ctx.has("a"));
    ctx.remove("a");
    EXPECT_FALSE(ctx.has("a"));
    EXPECT_TRUE(ctx.has("b"));
}

TEST(TaskContext, DataReturnsJson) {
    TaskContext ctx;
    ctx.set("x", "hello");
    ctx.set("y", 42);
    auto& d = ctx.data();
    EXPECT_TRUE(d.is_object());
    EXPECT_EQ(d["x"], "hello");
    EXPECT_EQ(d["y"], 42);
}

TEST(TaskContext, GetThrowsForMissing) {
    TaskContext ctx;
    EXPECT_THROW(ctx.get("nonexistent"), std::exception);
}

TEST(TaskContext, NestedJsonValues) {
    TaskContext ctx;
    nlohmann::json nested = {{"inner", {{"deep", true}}}};
    ctx.set("obj", nested);
    EXPECT_EQ(ctx.get("obj")["inner"]["deep"], true);
}

// --- TaskGraph additional tests ---

TEST(TaskGraph, GetNodeReturnsNullForMissing) {
    TaskGraph g("test");
    g.add<CodeNode>("exists", [](TaskContext ctx) { return ctx; });
    EXPECT_NE(g.getNode("exists"), nullptr);
    EXPECT_EQ(g.getNode("no_such_node"), nullptr);
}

TEST(TaskGraph, NodeOrderPreservesInsertion) {
    TaskGraph g("order");
    g.add<CodeNode>("c", [](TaskContext ctx) { return ctx; });
    g.add<CodeNode>("a", [](TaskContext ctx) { return ctx; });
    g.add<CodeNode>("b", [](TaskContext ctx) { return ctx; });

    auto& order = g.nodeOrder();
    ASSERT_EQ(order.size(), 3);
    EXPECT_EQ(order[0], "c");
    EXPECT_EQ(order[1], "a");
    EXPECT_EQ(order[2], "b");
}

TEST(TaskGraph, NameAccessor) {
    TaskGraph g("my_graph");
    EXPECT_EQ(g.name(), "my_graph");
}

TEST(TaskGraph, EdgesFromFiltering) {
    TaskGraph g("branching");
    auto d = g.add<DecisionCodeNode>("d", [](const TaskContext&) { return "a"; });
    auto a = g.add<CodeNode>("a", [](TaskContext ctx) { return ctx; });
    auto b = g.add<CodeNode>("b", [](TaskContext ctx) { return ctx; });
    auto c = g.add<CodeNode>("c", [](TaskContext ctx) { return ctx; });

    g.branch(d, "alpha", a);
    g.branch(d, "beta", b);
    g.edge(d, c); // default edge (empty branch)

    // edgesFrom with specific branch
    auto alpha = g.edgesFrom("d", "alpha");
    ASSERT_EQ(alpha.size(), 1);
    EXPECT_EQ(alpha[0]->to, "a");

    auto beta = g.edgesFrom("d", "beta");
    ASSERT_EQ(beta.size(), 1);
    EXPECT_EQ(beta[0]->to, "b");

    // edgesFrom with empty branch returns default edges only
    auto defaults = g.edgesFrom("d");
    ASSERT_EQ(defaults.size(), 1);
    EXPECT_EQ(defaults[0]->to, "c");
}

TEST(TaskGraph, AllEdgesFrom) {
    TaskGraph g("all_edges");
    auto n = g.add<CodeNode>("n", [](TaskContext ctx) { return ctx; });
    auto a = g.add<CodeNode>("a", [](TaskContext ctx) { return ctx; });
    auto b = g.add<CodeNode>("b", [](TaskContext ctx) { return ctx; });
    auto c = g.add<CodeNode>("c", [](TaskContext ctx) { return ctx; });

    g.edge(n, a);
    g.branch(n, "x", b);
    g.branch(n, "y", c);

    auto all = g.allEdgesFrom("n");
    EXPECT_EQ(all.size(), 3);

    // node with no outgoing edges
    auto none = g.allEdgesFrom("c");
    EXPECT_EQ(none.size(), 0);
}

TEST(TaskGraph, SetEntryOutputByString) {
    TaskGraph g("str");
    g.add<CodeNode>("first", [](TaskContext ctx) { return ctx; });
    g.add<CodeNode>("last", [](TaskContext ctx) { return ctx; });
    g.setEntry("first");
    g.setOutput("last");
    EXPECT_EQ(g.entry(), "first");
    EXPECT_EQ(g.output(), "last");
}

// --- GraphRunner additional tests ---

TEST(GraphRunner, SingleNodeGraph) {
    TaskGraph g("single");
    auto only = g.add<CodeNode>("only", [](TaskContext ctx) {
        ctx.set("ran", true);
        return ctx;
    });
    g.setEntry(only);
    // no edges, no output set

    GraphRunner runner;
    auto result = runner.run(g, TaskContext{});
    EXPECT_EQ(result.get("ran"), true);
}

TEST(GraphRunner, AllFanoutDiscarded) {
    TaskGraph g("all_discard");

    auto splitter = g.add<SplitterNode>("split", [](TaskContext) {
        std::vector<TaskContext> items;
        for (int i = 0; i < 3; i++) {
            TaskContext c;
            c.set("val", i);
            items.push_back(std::move(c));
        }
        return items;
    });

    auto discard = g.add<ExitNode>("discard");
    auto collector = g.add<CollectorNode>("collect");

    g.edge(splitter, discard);
    g.branch(splitter, "collect", collector);
    g.setEntry(splitter);
    g.setOutput(collector);

    GraphRunner runner;
    auto result = runner.run(g, TaskContext{});

    // Collector receives empty list — default merge produces empty array
    auto collected = result.get("collected");
    EXPECT_EQ(collected.size(), 0);
}

TEST(GraphRunner, DataAccumulatesThroughChain) {
    TaskGraph g("accum");

    auto a = g.add<CodeNode>("a", [](TaskContext ctx) { ctx.set("a", 1); return ctx; });
    auto b = g.add<CodeNode>("b", [](TaskContext ctx) { ctx.set("b", 2); return ctx; });
    auto c = g.add<CodeNode>("c", [](TaskContext ctx) {
        // Should see both a and b
        ctx.set("sum", ctx.get("a").get<int>() + ctx.get("b").get<int>());
        return ctx;
    });

    g.edge(a, b);
    g.edge(b, c);
    g.setEntry(a);
    g.setOutput(c);

    GraphRunner runner;
    TaskContext init;
    init.set("init", true);
    auto result = runner.run(g, std::move(init));

    EXPECT_EQ(result.get("init"), true);
    EXPECT_EQ(result.get("a"), 1);
    EXPECT_EQ(result.get("b"), 2);
    EXPECT_EQ(result.get("sum"), 3);
}

TEST(GraphRunner, UnknownBranchFallsToDefault) {
    TaskGraph g("fallback");

    auto decide = g.add<DecisionCodeNode>("decide", [](const TaskContext&) {
        return "unknown_branch";
    });
    auto fallback = g.add<CodeNode>("fallback", [](TaskContext ctx) {
        ctx.set("route", "default");
        return ctx;
    });
    auto specific = g.add<CodeNode>("specific", [](TaskContext ctx) {
        ctx.set("route", "specific");
        return ctx;
    });

    g.branch(decide, "known", specific);
    g.edge(decide, fallback); // default edge

    g.setEntry(decide);

    GraphRunner runner;
    auto result = runner.run(g, TaskContext{});
    EXPECT_EQ(result.get("route"), "default");
}

TEST(GraphRunner, SplitterWithoutCollector) {
    TaskGraph g("no_collector");

    auto splitter = g.add<SplitterNode>("split", [](TaskContext) {
        std::vector<TaskContext> items;
        TaskContext a; a.set("id", "first");
        TaskContext b; b.set("id", "second");
        items.push_back(std::move(a));
        items.push_back(std::move(b));
        return items;
    });

    auto process = g.add<CodeNode>("process", [](TaskContext ctx) {
        ctx.set("processed", true);
        return ctx;
    });

    g.edge(splitter, process);
    // No collector edge
    g.setEntry(splitter);

    GraphRunner runner;
    runner.setMaxParallel(1);
    auto result = runner.run(g, TaskContext{});

    // Returns first non-discarded result
    EXPECT_TRUE(result.get("processed").get<bool>());
}

TEST(GraphRunner, NodeNotFoundThrows) {
    TaskGraph g("bad_ref");
    auto a = g.add<CodeNode>("a", [](TaskContext ctx) { return ctx; });
    g.edge("a", "nonexistent");
    g.setEntry(a);

    GraphRunner runner;
    EXPECT_THROW(runner.run(g, TaskContext{}), std::runtime_error);
}

TEST(GraphRunner, SplitterNoDownstreamThrows) {
    TaskGraph g("no_downstream");

    auto splitter = g.add<SplitterNode>("split", [](TaskContext) {
        std::vector<TaskContext> items;
        items.push_back(TaskContext{});
        items.push_back(TaskContext{});
        return items;
    });

    // No edges from splitter at all
    g.setEntry(splitter);

    GraphRunner runner;
    EXPECT_THROW(runner.run(g, TaskContext{}), std::runtime_error);
}

TEST(GraphRunner, ExitNodeNullFn) {
    TaskGraph g("null_exit");
    auto exit = g.add<ExitNode>("exit"); // no function
    g.setEntry(exit);

    GraphRunner runner;
    auto result = runner.run(g, TaskContext{});
    EXPECT_TRUE(result.discarded);
}

// --- CollectorNode additional tests ---

TEST(CollectorNode, CustomFn) {
    TaskGraph g("custom_collect");

    auto splitter = g.add<SplitterNode>("split", [](TaskContext) {
        std::vector<TaskContext> items;
        for (int i = 1; i <= 3; i++) {
            TaskContext c;
            c.set("val", i);
            items.push_back(std::move(c));
        }
        return items;
    });

    auto pass = g.add<CodeNode>("pass", [](TaskContext ctx) { return ctx; });

    auto collector = g.add<CollectorNode>("collect", [](std::vector<TaskContext> items) {
        int sum = 0;
        for (auto& item : items) sum += item.get("val").get<int>();
        TaskContext result;
        result.set("total", sum);
        return result;
    });

    g.edge(splitter, pass);
    g.branch(splitter, "collect", collector);
    g.setEntry(splitter);
    g.setOutput(collector);

    GraphRunner runner;
    runner.setMaxParallel(1);
    auto result = runner.run(g, TaskContext{});

    EXPECT_EQ(result.get("total"), 6);
}

// --- json_extract tests ---

#include "graph/util/json_extract.h"

TEST(JsonExtract, FencedJsonBlock) {
    std::string input = "Here is the output:\n```json\n{\"key\": \"value\"}\n```\nDone.";
    auto result = extractJson(input);
    EXPECT_EQ(result, "{\"key\": \"value\"}\n");
}

TEST(JsonExtract, FencedBlockNoLanguage) {
    std::string input = "Result:\n```\n{\"a\": 1}\n```";
    auto result = extractJson(input);
    EXPECT_EQ(result, "{\"a\": 1}\n");
}

TEST(JsonExtract, RawJsonObject) {
    std::string input = "some text {\"x\": true} more text";
    auto result = extractJson(input);
    EXPECT_EQ(result, "{\"x\": true}");
}

TEST(JsonExtract, NestedBraces) {
    std::string input = R"({"outer": {"inner": 1}})";
    auto result = extractJson(input);
    EXPECT_EQ(result, R"({"outer": {"inner": 1}})");
}

TEST(JsonExtract, NoJsonReturnsOriginal) {
    std::string input = "no json here";
    auto result = extractJson(input);
    EXPECT_EQ(result, "no json here");
}

TEST(JsonExtract, EmptyString) {
    EXPECT_EQ(extractJson(""), "");
}
