.class public Lcom/example/download/FileDownloader;
.super Ljava/lang/Object;
.source "FileDownloader.java"

.field private context:Landroid/content/Context;
.field private downloadManager:Landroid/app/DownloadManager;

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/example/download/FileDownloader;->context:Landroid/content/Context;

    const-string v0, "download"
    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/app/DownloadManager;
    iput-object v0, p0, Lcom/example/download/FileDownloader;->downloadManager:Landroid/app/DownloadManager;
    return-void
.end method

.method public downloadFile(Ljava/lang/String;Ljava/lang/String;)J
    .locals 4
    .param p1, "url"
    .param p2, "filename"

    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v0

    new-instance v1, Landroid/app/DownloadManager$Request;
    invoke-direct {v1, v0}, Landroid/app/DownloadManager$Request;-><init>(Landroid/net/Uri;)V

    invoke-virtual {v1, p2}, Landroid/app/DownloadManager$Request;->setTitle(Ljava/lang/CharSequence;)Landroid/app/DownloadManager$Request;

    const-string v2, "Downloading file..."
    invoke-virtual {v1, v2}, Landroid/app/DownloadManager$Request;->setDescription(Ljava/lang/CharSequence;)Landroid/app/DownloadManager$Request;

    const/4 v2, 0x1
    invoke-virtual {v1, v2}, Landroid/app/DownloadManager$Request;->setNotificationVisibility(I)Landroid/app/DownloadManager$Request;

    sget-object v2, Landroid/os/Environment;->DIRECTORY_DOWNLOADS:Ljava/lang/String;
    invoke-virtual {v1, v2, p2}, Landroid/app/DownloadManager$Request;->setDestinationInExternalPublicDir(Ljava/lang/String;Ljava/lang/String;)Landroid/app/DownloadManager$Request;

    # Only allow HTTPS
    const/4 v2, 0x2
    invoke-virtual {v1, v2}, Landroid/app/DownloadManager$Request;->setAllowedNetworkTypes(I)Landroid/app/DownloadManager$Request;

    iget-object v3, p0, Lcom/example/download/FileDownloader;->downloadManager:Landroid/app/DownloadManager;
    invoke-virtual {v3, v1}, Landroid/app/DownloadManager;->enqueue(Landroid/app/DownloadManager$Request;)J
    move-result-wide v2
    return-wide v2
.end method

.method public cancelDownload(J)V
    .locals 1
    iget-object v0, p0, Lcom/example/download/FileDownloader;->downloadManager:Landroid/app/DownloadManager;
    invoke-virtual {v0, p1, p2}, Landroid/app/DownloadManager;->remove(J)I
    return-void
.end method
