.class public Lcom/example/model/UserModel;
.super Ljava/lang/Object;
.source "UserModel.java"

.implements Landroid/os/Parcelable;

.field private name:Ljava/lang/String;
.field private email:Ljava/lang/String;
.field private age:I

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/example/model/UserModel;->name:Ljava/lang/String;
    iput-object p2, p0, Lcom/example/model/UserModel;->email:Ljava/lang/String;
    iput p3, p0, Lcom/example/model/UserModel;->age:I
    return-void
.end method

.method public getName()Ljava/lang/String;
    .locals 1
    iget-object v0, p0, Lcom/example/model/UserModel;->name:Ljava/lang/String;
    return-object v0
.end method

.method public setName(Ljava/lang/String;)V
    .locals 0
    iput-object p1, p0, Lcom/example/model/UserModel;->name:Ljava/lang/String;
    return-void
.end method

.method public getEmail()Ljava/lang/String;
    .locals 1
    iget-object v0, p0, Lcom/example/model/UserModel;->email:Ljava/lang/String;
    return-object v0
.end method

.method public setEmail(Ljava/lang/String;)V
    .locals 0
    iput-object p1, p0, Lcom/example/model/UserModel;->email:Ljava/lang/String;
    return-void
.end method

.method public getAge()I
    .locals 1
    iget v0, p0, Lcom/example/model/UserModel;->age:I
    return v0
.end method

.method public setAge(I)V
    .locals 0
    iput p1, p0, Lcom/example/model/UserModel;->age:I
    return-void
.end method

.method public describeContents()I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 1
    iget-object v0, p0, Lcom/example/model/UserModel;->name:Ljava/lang/String;
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V
    iget-object v0, p0, Lcom/example/model/UserModel;->email:Ljava/lang/String;
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V
    iget v0, p0, Lcom/example/model/UserModel;->age:I
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "UserModel{name="
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    iget-object v1, p0, Lcom/example/model/UserModel;->name:Ljava/lang/String;
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    const-string v1, ", email="
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    iget-object v1, p0, Lcom/example/model/UserModel;->email:Ljava/lang/String;
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    const-string v1, "}"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
