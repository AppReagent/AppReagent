.class public Lcom/example/util/DateFormatter;
.super Ljava/lang/Object;
.source "DateFormatter.java"

.field private formatter:Ljava/text/SimpleDateFormat;

.method public constructor <init>()V
    .locals 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    new-instance v0, Ljava/text/SimpleDateFormat;
    const-string v1, "yyyy-MM-dd HH:mm:ss"
    invoke-direct {v0, v1}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;)V
    iput-object v0, p0, Lcom/example/util/DateFormatter;->formatter:Ljava/text/SimpleDateFormat;
    return-void
.end method

.method public formatDate(Ljava/util/Date;)Ljava/lang/String;
    .locals 1
    if-eqz p1, :ret_empty
    iget-object v0, p0, Lcom/example/util/DateFormatter;->formatter:Ljava/text/SimpleDateFormat;
    invoke-virtual {v0, p1}, Ljava/text/SimpleDateFormat;->format(Ljava/util/Date;)Ljava/lang/String;
    move-result-object v0
    return-object v0
    :ret_empty
    const-string v0, ""
    return-object v0
.end method

.method public parseDate(Ljava/lang/String;)Ljava/util/Date;
    .locals 1
    if-eqz p1, :ret_null
    iget-object v0, p0, Lcom/example/util/DateFormatter;->formatter:Ljava/text/SimpleDateFormat;
    invoke-virtual {v0, p1}, Ljava/text/SimpleDateFormat;->parse(Ljava/lang/String;)Ljava/util/Date;
    move-result-object v0
    return-object v0
    :ret_null
    const/4 v0, 0x0
    return-object v0
.end method

.method public formatTimestamp(J)Ljava/lang/String;
    .locals 2
    new-instance v0, Ljava/util/Date;
    invoke-direct {v0, p1, p2}, Ljava/util/Date;-><init>(J)V
    invoke-virtual {p0, v0}, Lcom/example/util/DateFormatter;->formatDate(Ljava/util/Date;)Ljava/lang/String;
    move-result-object v1
    return-object v1
.end method
