from cloud_db import save_alert, upsert_incident, expire_old_incidents

def persist(alert: dict):
    save_alert(alert)
    upsert_incident(alert)
    expire_old_incidents()   # ✅ THIS MAKES LIFECYCLE WORK
 
