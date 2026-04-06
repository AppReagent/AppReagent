.class public Lcom/example/maps/LocationService;
.super Landroid/app/Service;
.source "LocationService.java"

.field private fusedClient:Lcom/google/android/gms/location/FusedLocationProviderClient;
.field private locationCallback:Lcom/google/android/gms/location/LocationCallback;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Service;-><init>()V
    return-void
.end method

.method public onCreate()V
    .locals 2

    invoke-super {p0}, Landroid/app/Service;->onCreate()V

    invoke-static {p0}, Lcom/google/android/gms/location/LocationServices;->getFusedLocationProviderClient(Landroid/content/Context;)Lcom/google/android/gms/location/FusedLocationProviderClient;
    move-result-object v0
    iput-object v0, p0, Lcom/example/maps/LocationService;->fusedClient:Lcom/google/android/gms/location/FusedLocationProviderClient;

    new-instance v1, Lcom/example/maps/LocationService$Callback;
    invoke-direct {v1, p0}, Lcom/example/maps/LocationService$Callback;-><init>(Lcom/example/maps/LocationService;)V
    iput-object v1, p0, Lcom/example/maps/LocationService;->locationCallback:Lcom/google/android/gms/location/LocationCallback;
    return-void
.end method

.method public startLocationUpdates()V
    .locals 3

    new-instance v0, Lcom/google/android/gms/location/LocationRequest;
    invoke-direct {v0}, Lcom/google/android/gms/location/LocationRequest;-><init>()V

    const-wide/16 v1, 0x2710
    invoke-virtual {v0, v1, v2}, Lcom/google/android/gms/location/LocationRequest;->setInterval(J)Lcom/google/android/gms/location/LocationRequest;

    const/16 v1, 0x66
    invoke-virtual {v0, v1}, Lcom/google/android/gms/location/LocationRequest;->setPriority(I)Lcom/google/android/gms/location/LocationRequest;

    iget-object v1, p0, Lcom/example/maps/LocationService;->fusedClient:Lcom/google/android/gms/location/FusedLocationProviderClient;
    iget-object v2, p0, Lcom/example/maps/LocationService;->locationCallback:Lcom/google/android/gms/location/LocationCallback;
    invoke-virtual {v1, v0, v2}, Lcom/google/android/gms/location/FusedLocationProviderClient;->requestLocationUpdates(Lcom/google/android/gms/location/LocationRequest;Lcom/google/android/gms/location/LocationCallback;)V
    return-void
.end method

.method public stopLocationUpdates()V
    .locals 1
    iget-object v0, p0, Lcom/example/maps/LocationService;->fusedClient:Lcom/google/android/gms/location/FusedLocationProviderClient;
    if-eqz v0, :skip
    iget-object v0, p0, Lcom/example/maps/LocationService;->locationCallback:Lcom/google/android/gms/location/LocationCallback;
    iget-object v1, p0, Lcom/example/maps/LocationService;->fusedClient:Lcom/google/android/gms/location/FusedLocationProviderClient;
    invoke-virtual {v1, v0}, Lcom/google/android/gms/location/FusedLocationProviderClient;->removeLocationUpdates(Lcom/google/android/gms/location/LocationCallback;)V
    :skip
    return-void
.end method

.method public onLocationResult(Landroid/location/Location;)V
    .locals 2
    # Update the UI with new location — no network exfiltration
    const-string v0, "LocationService"
    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V
    const-string v0, "Location update: "
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {p1}, Landroid/location/Location;->getLatitude()D
    move-result-wide v0
    invoke-virtual {v1, v0, v1}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    const-string v1, "LocationService"
    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method
