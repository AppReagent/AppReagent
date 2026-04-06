.class public Lcom/example/push/PushHandler;
.super Lcom/google/firebase/messaging/FirebaseMessagingService;
.source "PushHandler.java"

.field private static final CHANNEL_ID:Ljava/lang/String; = "push_channel"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Lcom/google/firebase/messaging/FirebaseMessagingService;-><init>()V
    return-void
.end method

.method public onMessageReceived(Lcom/google/firebase/messaging/RemoteMessage;)V
    .locals 4

    invoke-virtual {p1}, Lcom/google/firebase/messaging/RemoteMessage;->getNotification()Lcom/google/firebase/messaging/RemoteMessage$Notification;
    move-result-object v0
    if-eqz v0, :skip

    invoke-virtual {v0}, Lcom/google/firebase/messaging/RemoteMessage$Notification;->getTitle()Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v0}, Lcom/google/firebase/messaging/RemoteMessage$Notification;->getBody()Ljava/lang/String;
    move-result-object v2

    invoke-virtual {p0, v1, v2}, Lcom/example/push/PushHandler;->showNotification(Ljava/lang/String;Ljava/lang/String;)V

    :skip
    return-void
.end method

.method private showNotification(Ljava/lang/String;Ljava/lang/String;)V
    .locals 5

    new-instance v0, Landroid/support/v4/app/NotificationCompat$Builder;
    const-string v1, "push_channel"
    invoke-direct {v0, p0, v1}, Landroid/support/v4/app/NotificationCompat$Builder;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    const v1, 0x7f080010
    invoke-virtual {v0, v1}, Landroid/support/v4/app/NotificationCompat$Builder;->setSmallIcon(I)Landroid/support/v4/app/NotificationCompat$Builder;
    invoke-virtual {v0, p1}, Landroid/support/v4/app/NotificationCompat$Builder;->setContentTitle(Ljava/lang/CharSequence;)Landroid/support/v4/app/NotificationCompat$Builder;
    invoke-virtual {v0, p2}, Landroid/support/v4/app/NotificationCompat$Builder;->setContentText(Ljava/lang/CharSequence;)Landroid/support/v4/app/NotificationCompat$Builder;

    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Landroid/support/v4/app/NotificationCompat$Builder;->setAutoCancel(Z)Landroid/support/v4/app/NotificationCompat$Builder;

    const-string v2, "notification"
    invoke-virtual {p0, v2}, Landroid/app/Service;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v2
    check-cast v2, Landroid/app/NotificationManager;

    invoke-virtual {v0}, Landroid/support/v4/app/NotificationCompat$Builder;->build()Landroid/app/Notification;
    move-result-object v3

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J
    move-result-wide v3
    long-to-int v4, v3
    invoke-virtual {v0}, Landroid/support/v4/app/NotificationCompat$Builder;->build()Landroid/app/Notification;
    move-result-object v3
    invoke-virtual {v2, v4, v3}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V
    return-void
.end method

.method public onNewToken(Ljava/lang/String;)V
    .locals 2
    const-string v0, "PushHandler"
    const-string v1, "FCM token refreshed"
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method
