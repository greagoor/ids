import psycopg2
from core.severity import severity_to_int


conn = psycopg2.connect(
    "postgresql://postgres.nqhmyubxbemwhckqzyjm:supabasegreagoor90@aws-1-ap-northeast-1.pooler.supabase.com:5432/postgres"
)

print("Connected to Supabase via pooler")


def save_alert(alert):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts
            (timestamp, src_ip, attack_type, severity, outcome, confidence, method, uri)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                alert["timestamp"],
                alert["src_ip"],
                alert["attack_type"],
                severity_to_int(alert["severity"]),
                alert["outcome"],
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

        if row is not None:
            incident_id, count, last_seen = row
            last_seen = last_seen.astimezone(timezone.utc)

            if now - last_seen > TIME_WINDOW:
                new_count = 1
            else:
                new_count = count + 1

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
                    severity = %s,
                    status = 'ACTIVE'
                WHERE id = %s
                """,
                (new_count, alert["timestamp"], severity, incident_id)
            )

        else:
            cur.execute(
                """
                INSERT INTO incidents
                (src_ip, attack_type, count, first_seen, last_seen, severity, status)
                VALUES (%s, %s, 1, %s, %s, %s, 'ACTIVE')
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


def expire_old_incidents():
    with psycopg2.connect(
        "postgresql://postgres.nqhmyubxbemwhckqzyjm:supabasegreagoor90@aws-1-ap-northeast-1.pooler.supabase.com:5432/postgres"
    ) as local_conn:
        with local_conn.cursor() as cur:
            cur.execute(
                """
                UPDATE incidents
                SET status = 'EXPIRED'
                WHERE status = 'ACTIVE'
                  AND last_seen < now() - interval '10 minutes'
                """
            )
            local_conn.commit()


def decay_incident_severity():
    with psycopg2.connect(
        "postgresql://postgres.nqhmyubxbemwhckqzyjm:supabasegreagoor90@aws-1-ap-northeast-1.pooler.supabase.com:5432/postgres"
    ) as local_conn:
        with local_conn.cursor() as cur:
            cur.execute(
                """
                UPDATE incidents
                SET severity = CASE
                    WHEN severity = 'CRITICAL'
                         AND last_seen < now() - interval '5 minutes'
                        THEN 'HIGH'

                    WHEN severity = 'HIGH'
                         AND last_seen < now() - interval '10 minutes'
                        THEN 'MEDIUM'

                    WHEN severity = 'MEDIUM'
                         AND last_seen < now() - interval '20 minutes'
                        THEN 'LOW'

                    ELSE severity
                END
                WHERE status = 'ACTIVE';
                """
            )
            local_conn.commit()



