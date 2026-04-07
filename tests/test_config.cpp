#include <gtest/gtest.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include "infra/config/Config.h"

class ConfigTest : public ::testing::Test {
protected:
    std::string tmpPath = "/tmp/area_test_config.json";

    void writeConfig(const nlohmann::json& j) {
        std::ofstream f(tmpPath);
        f << j.dump();
    }

    void TearDown() override {
        std::remove(tmpPath.c_str());
    }
};

TEST_F(ConfigTest, LoadsEndpointsWithExplicitModel) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
        {"ai_endpoints", {{
            {"id", "mini1"},
            {"provider", "ollama"},
            {"url", "http://192.168.1.1:11434"},
            {"model", "glm-4.7-flash"}
        }}}
    });

    auto c = area::Config::load(tmpPath);
    ASSERT_EQ(c.ai_endpoints.size(), 1);
    EXPECT_EQ(c.ai_endpoints[0].id, "mini1");
    EXPECT_EQ(c.ai_endpoints[0].provider, "ollama");
    EXPECT_EQ(c.ai_endpoints[0].url, "http://192.168.1.1:11434");
    EXPECT_EQ(c.ai_endpoints[0].model, "glm-4.7-flash");
}

TEST_F(ConfigTest, ModelDefaultsToAuto) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
        {"ai_endpoints", {{
            {"id", "mini1"},
            {"provider", "ollama"},
            {"url", "http://192.168.1.1:11434"}
        }}}
    });

    auto c = area::Config::load(tmpPath);
    EXPECT_EQ(c.ai_endpoints[0].model, "auto");
}

TEST_F(ConfigTest, UrlDefaultsToEmpty) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
        {"ai_endpoints", {{
            {"id", "test"},
            {"provider", "mock"}
        }}}
    });

    auto c = area::Config::load(tmpPath);
    EXPECT_EQ(c.ai_endpoints[0].url, "");
    EXPECT_EQ(c.ai_endpoints[0].provider, "mock");
}

TEST_F(ConfigTest, BatchSizeDefaultsTo10) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
    });

    auto c = area::Config::load(tmpPath);
    EXPECT_EQ(c.job_batch_size, 10);
}

TEST_F(ConfigTest, BatchSizeOverride) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
        {"job_batch_size", 25}
    });

    auto c = area::Config::load(tmpPath);
    EXPECT_EQ(c.job_batch_size, 25);
}

TEST_F(ConfigTest, MultipleEndpoints) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
        {"ai_endpoints", {
            {{"id", "a"}, {"provider", "ollama"}, {"url", "http://a:11434"}},
            {{"id", "b"}, {"provider", "lmstudio"}, {"url", "http://b:1234"}, {"model", "qwen2.5-coder-14b"}},
            {{"id", "c"}, {"provider", "mock"}}
        }}
    });

    auto c = area::Config::load(tmpPath);
    ASSERT_EQ(c.ai_endpoints.size(), 3);
    EXPECT_EQ(c.ai_endpoints[0].provider, "ollama");
    EXPECT_EQ(c.ai_endpoints[1].model, "qwen2.5-coder-14b");
    EXPECT_EQ(c.ai_endpoints[2].provider, "mock");
}

TEST_F(ConfigTest, MissingFileThrows) {
    EXPECT_THROW(area::Config::load("/tmp/nonexistent_area_config.json"), std::runtime_error);
}

TEST_F(ConfigTest, TierDefaultsToZero) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
        {"ai_endpoints", {{
            {"id", "mini1"},
            {"provider", "ollama"},
            {"url", "http://a:11434"}
        }}}
    });

    auto c = area::Config::load(tmpPath);
    EXPECT_EQ(c.ai_endpoints[0].tier, 0);
    EXPECT_EQ(c.ai_endpoints[0].max_concurrent, 1);
}

TEST_F(ConfigTest, TierExplicit) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
        {"ai_endpoints", {{
            {"id", "gpu"},
            {"provider", "lmstudio"},
            {"url", "http://gpu:1234"},
            {"tier", 2},
            {"max_concurrent", 4}
        }}}
    });

    auto c = area::Config::load(tmpPath);
    EXPECT_EQ(c.ai_endpoints[0].tier, 2);
    EXPECT_EQ(c.ai_endpoints[0].max_concurrent, 4);
}

TEST_F(ConfigTest, FlushTimeoutDefault) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
    });

    auto c = area::Config::load(tmpPath);
    EXPECT_EQ(c.flush_timeout_sec, 15);
}

TEST_F(ConfigTest, FlushTimeoutOverride) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
        {"flush_timeout_sec", 30}
    });

    auto c = area::Config::load(tmpPath);
    EXPECT_EQ(c.flush_timeout_sec, 30);
}

TEST_F(ConfigTest, ThreeTierEndpoints) {
    writeConfig({
        {"postgres_url", "postgresql://localhost/test"},
        {"postgres_cert", "cert.crt"},
        {"ai_endpoints", {
            {{"id", "low1"}, {"provider", "mock"}},
            {{"id", "low2"}, {"provider", "mock"}, {"tier", 0}},
            {{"id", "med1"}, {"provider", "mock"}, {"tier", 1}, {"max_concurrent", 1}},
            {{"id", "high1"}, {"provider", "mock"}, {"tier", 2}, {"max_concurrent", 2}},
        }}
    });

    auto c = area::Config::load(tmpPath);
    ASSERT_EQ(c.ai_endpoints.size(), 4);
    EXPECT_EQ(c.ai_endpoints[0].tier, 0);
    EXPECT_EQ(c.ai_endpoints[1].tier, 0);
    EXPECT_EQ(c.ai_endpoints[2].tier, 1);
    EXPECT_EQ(c.ai_endpoints[3].tier, 2);
    EXPECT_EQ(c.ai_endpoints[3].max_concurrent, 2);
}
