import json
import random
import string
import subprocess
from datetime import datetime, timezone

# === CONFIG ===
REGION = "us-east-1"
SURVEYS_TABLE = "loop_surveys"
MATCHES_TABLE = "loop_matches"
MATCHMAKER_FUNCTION_NAME = "loop_matchmaker"
N_USERS = 30

ORIENTATIONS = ["stabilizing", "exploratory", "rebuilding", "expanding", "reflective", "open"]
SIGNALS = ["novelty", "reframe", "grounded", "provocation", "stillness", "surprise"]
CONNECTION = ["quiet_reflection", "thoughtful_back_and_forth", "creative_exchange",
              "practical_problem_solving", "open_ended_wandering", "depends"]
BIAS = ["text", "visual", "audio", "systems", "dialogue", "patterns", None]
CADENCE = ["rare", "light", "steady", "unknown"]

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def now_epoch():
    return str(int(datetime.now(timezone.utc).timestamp()))

def week_id():
    y, w, _ = datetime.now(timezone.utc).isocalendar()
    return f"{y}-W{w:02d}"

def rand_name():
    return random.choice(["Javier","Sam","Maya","Noah","Ava","Lina","Iris","Leo","Kai","Zoe","Rae","Miles","Nico","Sofia","Jules", "Daisy", "Erika", "Niles", "Harrison"])

def make_answers():
    # choose 1-2 desired signals
    desired = random.sample(SIGNALS, k=random.choice([1,2]))
    return {
        "firstName": {"S": rand_name()},
        "orientation": {"S": random.choice(ORIENTATIONS)},
        "desired_signals": {"L": [{"S": s} for s in desired]},
        "attention_bias": {"S": random.choice([b for b in BIAS if b])} if random.random() > 0.25 else {"NULL": True},
        "connection_style": {"S": random.choice(CONNECTION)},
        "cadence": {"S": random.choice(CADENCE)},
        "source": {"S": random.choice(["friend","x","instagram","newsletter","random_link","other"])},
        "pause_reason": {"S": random.choice(["music","curiosity","timing","friends","signal"])} if random.random() > 0.5 else {"NULL": True},
        "anti_signal": {"S": random.choice(["not hype", "not dating", "not spam", "not another feed"])} if random.random() > 0.85 else {"NULL": True},
        "never_forget": {"NULL": True},
        "consent": {"BOOL": True},
        "submitted_at": {"S": now_iso()},
    }

def aws(*args):
    cmd = ["aws", *args, "--region", REGION]
    out = subprocess.check_output(cmd)
    return out.decode("utf-8")

def put_survey(email):
    answers = make_answers()
    item = {
        "pk": {"S": email},
        "sk": {"S": f"SURVEY#{now_iso()}"},
        "email": {"S": email},
        "created_at_epoch": {"N": now_epoch()},
        "submitted_at": {"S": now_iso()},
        # answers is stored as a STRING containing JSON
        "answers": {"S": json.dumps(answers)},
    }

    aws("dynamodb", "put-item",
        "--table-name", SURVEYS_TABLE,
        "--item", json.dumps(item)
    )

def invoke_matchmaker():
    # invoke with empty payload
    aws("lambda", "invoke",
        "--function-name", MATCHMAKER_FUNCTION_NAME,
        "--payload", "{}",
        "invoke_out.json"
    )
    print("Lambda invoke response:", open("invoke_out.json").read())

def list_matches_for_week():
    wid = week_id()
    # query the GSI by week_id
    resp = aws("dynamodb", "query",
        "--table-name", MATCHES_TABLE,
        "--index-name", "gsi_week",
        "--key-condition-expression", "gsi1pk = :w",
        "--expression-attribute-values", json.dumps({":w": {"S": wid}})
    )
    data = json.loads(resp)
    items = data.get("Items", [])
    print(f"\nMatches for {wid}: {len(items)} records\n")

    # pretty print a few
    for it in items[:25]:
        user = it["user_pk"]["S"]
        match = it["matched_user_pk"]["S"]
        score = int(it["score"]["N"])
        explain = it.get("explain", {}).get("S", "")
        print(f"{user:28} -> {match:28}  score={score:2d}  ({explain})")

if __name__ == "__main__":
    # seed users
    for i in range(N_USERS):
        email = f"synthetic+{i}-{''.join(random.choices(string.ascii_lowercase, k=6))}@example.com"
        put_survey(email)

    # print(f"Seeded {N_USERS} synthetic surveys into {SURVEYS_TABLE}.")

    # # run matchmaking
    # invoke_matchmaker()

    # # show matches
    # list_matches_for_week()
