.class public Lcom/example/ui/RecyclerAdapter;
.super Landroid/support/v7/widget/RecyclerView$Adapter;
.source "RecyclerAdapter.java"

.field private items:Ljava/util/List;

.method public constructor <init>(Ljava/util/List;)V
    .locals 0
    invoke-direct {p0}, Landroid/support/v7/widget/RecyclerView$Adapter;-><init>()V
    iput-object p1, p0, Lcom/example/ui/RecyclerAdapter;->items:Ljava/util/List;
    return-void
.end method

.method public onCreateViewHolder(Landroid/view/ViewGroup;I)Landroid/support/v7/widget/RecyclerView$ViewHolder;
    .locals 3

    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;
    move-result-object v0

    const v1, 0x7f040001
    const/4 v2, 0x0
    invoke-virtual {v0, v1, p1, v2}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;
    move-result-object v0

    new-instance v1, Lcom/example/ui/RecyclerAdapter$ViewHolder;
    invoke-direct {v1, v0}, Lcom/example/ui/RecyclerAdapter$ViewHolder;-><init>(Landroid/view/View;)V
    return-object v1
.end method

.method public onBindViewHolder(Landroid/support/v7/widget/RecyclerView$ViewHolder;I)V
    .locals 2

    iget-object v0, p0, Lcom/example/ui/RecyclerAdapter;->items:Ljava/util/List;
    invoke-interface {v0, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Ljava/lang/String;

    check-cast p1, Lcom/example/ui/RecyclerAdapter$ViewHolder;

    const v1, 0x7f080002
    iget-object v1, p1, Lcom/example/ui/RecyclerAdapter$ViewHolder;->textView:Landroid/widget/TextView;
    invoke-virtual {v1, v0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
    return-void
.end method

.method public getItemCount()I
    .locals 1
    iget-object v0, p0, Lcom/example/ui/RecyclerAdapter;->items:Ljava/util/List;
    invoke-interface {v0}, Ljava/util/List;->size()I
    move-result v0
    return v0
.end method
