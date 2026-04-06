.class public Lcom/example/util/StringUtils;
.super Ljava/lang/Object;
.source "StringUtils.java"

.method private constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static isEmpty(Ljava/lang/String;)Z
    .locals 1
    if-eqz p0, :yes
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v0
    if-eqz v0, :yes
    const/4 v0, 0x0
    return v0
    :yes
    const/4 v0, 0x1
    return v0
.end method

.method public static capitalize(Ljava/lang/String;)Ljava/lang/String;
    .locals 3
    if-eqz p0, :ret_null
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v0
    if-eqz v0, :ret_empty

    const/4 v0, 0x0
    invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C
    move-result v0
    invoke-static {v0}, Ljava/lang/Character;->toUpperCase(C)C
    move-result v0

    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
    const/4 v2, 0x1
    invoke-virtual {p0, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0

    :ret_null
    const/4 v0, 0x0
    return-object v0
    :ret_empty
    return-object p0
.end method

.method public static trim(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    if-eqz p0, :ret_null
    invoke-virtual {p0}, Ljava/lang/String;->trim()Ljava/lang/String;
    move-result-object v0
    return-object v0
    :ret_null
    const/4 v0, 0x0
    return-object v0
.end method

.method public static join(Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;
    .locals 4

    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const/4 v1, 0x0
    invoke-interface {p0}, Ljava/util/List;->size()I
    move-result v2

    :loop
    if-ge v1, v2, :done

    if-eqz v1, :no_sep
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    :no_sep

    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;
    move-result-object v3
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;
    add-int/lit8 v1, v1, 0x1
    goto :loop

    :done
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
