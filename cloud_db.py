import psycopg2

conn = psycopg2.connect(
    "postgresql://postgres.nqhmyubxbemwhckqzyjm:supabasegreagoor90@aws-1-ap-northeast-1.pooler.supabase.com:5432/postgres"
)

print("Connected to Supabase via pooler")


def save_alert(alert):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts
            (timestamp, src_ip, attack_type, outcome, confidence, method, uri)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                alert["timestamp"],
                alert["src_ip"],
                alert["attack_type"],
                alert["outcome"],   # this is the OUTCOME value
                alert["confidence"],
                alert["method"],
                alert["uri"]
            )
        )
        conn.commit()



from datetime import datetime, timezone, timedelta


TIME_WINDOW = timedelta(minutes=10)


def upsert_incident(alert):
    now = datetime.fromisoformat(alert["timestamp"])

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, count, last_seen FROM incidents
            WHERE src_ip = %s AND attack_type = %s
            """,
            (alert["src_ip"], alert["attack_type"])
        )

        row = cur.fetchone()

        if row:
            incident_id, count, last_seen = row

            # Convert DB timestamptz → Python datetime
            last_seen = last_seen.astimezone(timezone.utc)

            # ⏱️ TIME WINDOW CHECK
            if now - last_seen > TIME_WINDOW:
                # Reset incident
                new_count = 1
            else:
                new_count = count + 1

            # 🔥 SEVERITY ESCALATION
            if new_count >= 5:
                severity = "CRITICAL"
            elif new_count >= 3:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            cur.execute(
                """
                UPDATE incidents
                SET count = %s,
                    last_seen = %s,
                    severity = %s
                WHERE id = %s
                """,
                (new_count, alert["timestamp"], severity, incident_id)
            )

        else:
            # First ever incident
            cur.execute(
                """
                INSERT INTO incidents
                (src_ip, attack_type, count, first_seen, last_seen, severity)
                VALUES (%s, %s, 1, %s, %s, %s)
                """,
                (
                    alert["src_ip"],
                    alert["attack_type"],
                    alert["timestamp"],
                    alert["timestamp"],
                    "MEDIUM"
                )
            )

        conn.commit()
