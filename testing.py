import json
items = json.load(open("matches.json"))["Items"]
print("unique matched users:", len({it["user_pk"]["S"] for it in items}))
