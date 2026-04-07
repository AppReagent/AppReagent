.class public Lcom/example/app/BenignActivity;
.super Landroid/app/Activity;
.source "BenignActivity.java"

.field private textView:Landroid/widget/TextView;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 2

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    const v0, 0x7f030001

    invoke-virtual {p0, v0}, Lcom/example/app/BenignActivity;->setContentView(I)V

    const v0, 0x7f080001

    invoke-virtual {p0, v0}, Lcom/example/app/BenignActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/TextView;

    iput-object v0, p0, Lcom/example/app/BenignActivity;->textView:Landroid/widget/TextView;

    const-string v1, "Hello World!"

    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public onResume()V
    .locals 1

    invoke-super {p0}, Landroid/app/Activity;->onResume()V

    const-string v0, "Activity resumed"

    invoke-static {v0, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method
