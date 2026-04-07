#include <gtest/gtest.h>
#include "domains/smali/parser.h"

static const char* SAMPLE_SMALI = R"(
.class public Lcom/example/Malware;
.super Ljava/lang/Object;
.source "Malware.java"

.implements Ljava/lang/Runnable;

.field private secret:Ljava/lang/String;
.field public static TAG:Ljava/lang/String;

.method public constructor <init>()V
    .registers 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public sendSMS(Ljava/lang/String;Ljava/lang/String;)V
    .registers 4

    sget-object v0, Lcom/example/Malware;->TAG:Ljava/lang/String;
    invoke-static {}, Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;
    move-result-object v0
    invoke-virtual {v0, p1, p0, p2, p0, p0}, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V
    return-void
.end method

.method private decrypt([B)[B
    .registers 5

    invoke-static {p1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v0
    return-object v0
.end method
)";

TEST(SmaliParser, ParsesClassName) {
    auto f = area::smali::parse(SAMPLE_SMALI);
    EXPECT_EQ(f.class_name, "Lcom/example/Malware;");
}

TEST(SmaliParser, ParsesSuperClass) {
    auto f = area::smali::parse(SAMPLE_SMALI);
    EXPECT_EQ(f.super_class, "Ljava/lang/Object;");
}

TEST(SmaliParser, ParsesSourceFile) {
    auto f = area::smali::parse(SAMPLE_SMALI);
    EXPECT_EQ(f.source_file, "Malware.java");
}

TEST(SmaliParser, ParsesInterfaces) {
    auto f = area::smali::parse(SAMPLE_SMALI);
    ASSERT_EQ(f.interfaces.size(), 1);
    EXPECT_EQ(f.interfaces[0], "Ljava/lang/Runnable;");
}

TEST(SmaliParser, ParsesFields) {
    auto f = area::smali::parse(SAMPLE_SMALI);
    ASSERT_EQ(f.fields.size(), 2);
    EXPECT_EQ(f.fields[0].name, "secret");
    EXPECT_EQ(f.fields[0].type, "Ljava/lang/String;");
    EXPECT_EQ(f.fields[0].access, "private");
    EXPECT_EQ(f.fields[1].name, "TAG");
    EXPECT_EQ(f.fields[1].access, "public static");
}

TEST(SmaliParser, ParsesMethods) {
    auto f = area::smali::parse(SAMPLE_SMALI);
    ASSERT_EQ(f.methods.size(), 3);

    EXPECT_EQ(f.methods[0].name, "<init>");
    EXPECT_EQ(f.methods[0].access, "public constructor");

    EXPECT_EQ(f.methods[1].name, "sendSMS");
    EXPECT_EQ(f.methods[1].access, "public");
    EXPECT_EQ(f.methods[1].signature, "(Ljava/lang/String;Ljava/lang/String;)V");

    EXPECT_EQ(f.methods[2].name, "decrypt");
    EXPECT_EQ(f.methods[2].access, "private");
}

TEST(SmaliParser, MethodBodiesPreserved) {
    auto f = area::smali::parse(SAMPLE_SMALI);

    // sendSMS should contain SmsManager
    EXPECT_NE(f.methods[1].body.find("SmsManager"), std::string::npos);

    // decrypt should contain Cipher
    EXPECT_NE(f.methods[2].body.find("Cipher"), std::string::npos);

    // Each body starts with .method and ends with .end method
    for (auto& m : f.methods) {
        EXPECT_NE(m.body.find(".method"), std::string::npos);
        EXPECT_NE(m.body.find(".end method"), std::string::npos);
    }
}

TEST(SmaliParser, EmptyFile) {
    auto f = area::smali::parse("");
    EXPECT_TRUE(f.class_name.empty());
    EXPECT_TRUE(f.methods.empty());
    EXPECT_TRUE(f.fields.empty());
}

TEST(SmaliParser, LineNumbers) {
    auto f = area::smali::parse(SAMPLE_SMALI);
    for (auto& m : f.methods) {
        EXPECT_GT(m.line_start, 0);
        EXPECT_GT(m.line_end, m.line_start);
    }
}

TEST(SmaliParser, ExtractCalls_InvokeVirtual) {
    std::string body = R"(.method public sendSMS(Ljava/lang/String;Ljava/lang/String;)V
    .registers 4
    invoke-static {}, Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;
    move-result-object v0
    invoke-virtual {v0, p1, p0, p2, p0, p0}, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V
    return-void
.end method)";

    auto calls = area::smali::extractCalls(body);
    ASSERT_EQ(calls.size(), 2);

    EXPECT_EQ(calls[0].invoke_type, "static");
    EXPECT_EQ(calls[0].target_class, "Landroid/telephony/SmsManager;");
    EXPECT_EQ(calls[0].target_method, "getDefault");

    EXPECT_EQ(calls[1].invoke_type, "virtual");
    EXPECT_EQ(calls[1].target_class, "Landroid/telephony/SmsManager;");
    EXPECT_EQ(calls[1].target_method, "sendTextMessage");
}

TEST(SmaliParser, ExtractCalls_InvokeDirect) {
    std::string body = R"(.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method)";

    auto calls = area::smali::extractCalls(body);
    ASSERT_EQ(calls.size(), 1);
    EXPECT_EQ(calls[0].invoke_type, "direct");
    EXPECT_EQ(calls[0].target_class, "Ljava/lang/Object;");
    EXPECT_EQ(calls[0].target_method, "<init>");
    EXPECT_EQ(calls[0].target_signature, "()V");
}

TEST(SmaliParser, ExtractCalls_NoInvokes) {
    std::string body = R"(.method private getKey()[B
    .registers 2
    const/4 v0, 0x10
    new-array v0, v0, [B
    return-object v0
.end method)";

    auto calls = area::smali::extractCalls(body);
    EXPECT_TRUE(calls.empty());
}

TEST(SmaliParser, ExtractCalls_AllFromSampleFile) {
    auto f = area::smali::parse(SAMPLE_SMALI);

    // sendSMS method should have calls to SmsManager
    auto sendSmsCalls = area::smali::extractCalls(f.methods[1].body);
    EXPECT_GE(sendSmsCalls.size(), 2);

    // Check that at least one call targets SmsManager
    bool foundSmsManager = false;
    for (auto& c : sendSmsCalls) {
        if (c.target_class.find("SmsManager") != std::string::npos) {
            foundSmsManager = true;
            break;
        }
    }
    EXPECT_TRUE(foundSmsManager);

    // decrypt method should call Cipher.getInstance
    auto decryptCalls = area::smali::extractCalls(f.methods[2].body);
    EXPECT_GE(decryptCalls.size(), 1);
    EXPECT_EQ(decryptCalls[0].target_method, "getInstance");
}
