.class public Lcom/example/ui/CustomView;
.super Landroid/view/View;
.source "CustomView.java"

.field private paint:Landroid/graphics/Paint;
.field private radius:F
.field private color:I

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 2
    invoke-direct {p0, p1, p2}, Landroid/view/View;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    new-instance v0, Landroid/graphics/Paint;
    invoke-direct {v0}, Landroid/graphics/Paint;-><init>()V
    iput-object v0, p0, Lcom/example/ui/CustomView;->paint:Landroid/graphics/Paint;

    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setAntiAlias(Z)V

    const/high16 v1, 0x42c80000
    iput v1, p0, Lcom/example/ui/CustomView;->radius:F

    const v1, 0xff4285f4
    iput v1, p0, Lcom/example/ui/CustomView;->color:I
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setColor(I)V
    return-void
.end method

.method protected onDraw(Landroid/graphics/Canvas;)V
    .locals 4

    invoke-super {p0, p1}, Landroid/view/View;->onDraw(Landroid/graphics/Canvas;)V

    invoke-virtual {p0}, Landroid/view/View;->getWidth()I
    move-result v0
    div-int/lit8 v0, v0, 0x2
    int-to-float v0, v0

    invoke-virtual {p0}, Landroid/view/View;->getHeight()I
    move-result v1
    div-int/lit8 v1, v1, 0x2
    int-to-float v1, v1

    iget v2, p0, Lcom/example/ui/CustomView;->radius:F
    iget-object v3, p0, Lcom/example/ui/CustomView;->paint:Landroid/graphics/Paint;

    invoke-virtual {p1, v0, v1, v2, v3}, Landroid/graphics/Canvas;->drawCircle(FFFLandroid/graphics/Paint;)V
    return-void
.end method

.method protected onMeasure(II)V
    .locals 2

    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getSize(I)I
    move-result v0
    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getSize(I)I
    move-result v1

    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I
    move-result v0

    invoke-virtual {p0, v0, v0}, Landroid/view/View;->setMeasuredDimension(II)V
    return-void
.end method

.method public setRadius(F)V
    .locals 0
    iput p1, p0, Lcom/example/ui/CustomView;->radius:F
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V
    return-void
.end method

.method public setColor(I)V
    .locals 1
    iput p1, p0, Lcom/example/ui/CustomView;->color:I
    iget-object v0, p0, Lcom/example/ui/CustomView;->paint:Landroid/graphics/Paint;
    invoke-virtual {v0, p1}, Landroid/graphics/Paint;->setColor(I)V
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V
    return-void
.end method
