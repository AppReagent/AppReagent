.class public Lcom/example/analytics/AnalyticsTracker;
.super Ljava/lang/Object;
.source "AnalyticsTracker.java"

.field private static instance:Lcom/example/analytics/AnalyticsTracker;
.field private endpoint:Ljava/lang/String;
.field private events:Ljava/util/List;

.method private constructor <init>()V
    .locals 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    const-string v0, "https://analytics.example.com/v2/events"
    iput-object v0, p0, Lcom/example/analytics/AnalyticsTracker;->endpoint:Ljava/lang/String;
    new-instance v0, Ljava/util/ArrayList;
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V
    iput-object v0, p0, Lcom/example/analytics/AnalyticsTracker;->events:Ljava/util/List;
    return-void
.end method

.method public static getInstance()Lcom/example/analytics/AnalyticsTracker;
    .locals 1
    sget-object v0, Lcom/example/analytics/AnalyticsTracker;->instance:Lcom/example/analytics/AnalyticsTracker;
    if-nez v0, :ret
    new-instance v0, Lcom/example/analytics/AnalyticsTracker;
    invoke-direct {v0}, Lcom/example/analytics/AnalyticsTracker;-><init>()V
    sput-object v0, Lcom/example/analytics/AnalyticsTracker;->instance:Lcom/example/analytics/AnalyticsTracker;
    :ret
    return-object v0
.end method

.method public trackScreenView(Ljava/lang/String;)V
    .locals 3
    .param p1, "screenName"

    new-instance v0, Lorg/json/JSONObject;
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    const-string v1, "event"
    const-string v2, "screen_view"
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    const-string v1, "screen"
    invoke-virtual {v0, v1, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    const-string v1, "timestamp"
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J
    move-result-wide v2
    invoke-virtual {v0, v1, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;J)Lorg/json/JSONObject;

    iget-object v1, p0, Lcom/example/analytics/AnalyticsTracker;->events:Ljava/util/List;
    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;
    move-result-object v2
    invoke-interface {v1, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    return-void
.end method

.method public flush()V
    .locals 5

    iget-object v0, p0, Lcom/example/analytics/AnalyticsTracker;->events:Ljava/util/List;
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z
    move-result v1
    if-nez v1, :skip

    new-instance v1, Ljava/net/URL;
    iget-object v2, p0, Lcom/example/analytics/AnalyticsTracker;->endpoint:Ljava/lang/String;
    invoke-direct {v1, v2}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v2
    check-cast v2, Ljava/net/HttpURLConnection;

    const-string v3, "POST"
    invoke-virtual {v2, v3}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V
    const-string v3, "Content-Type"
    const-string v4, "application/json"
    invoke-virtual {v2, v3, v4}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    const/4 v3, 0x1
    invoke-virtual {v2, v3}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;
    move-result-object v3
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    move-result-object v4
    invoke-virtual {v4}, Ljava/lang/String;->getBytes()[B
    move-result-object v4
    invoke-virtual {v3, v4}, Ljava/io/OutputStream;->write([B)V
    invoke-virtual {v3}, Ljava/io/OutputStream;->close()V

    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getResponseCode()I
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->disconnect()V

    invoke-interface {v0}, Ljava/util/List;->clear()V

    :skip
    return-void
.end method
