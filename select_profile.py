import json
import os

profiles = [
    "Engineer",
    "Lawyer",
    "HR",
    "Finance",
    "Manager",
    "IT Admin",
    "Sales",
    "Normal Employee"
]

print("=" * 50)
print("DLP ACTIVE PROFILE SELECTOR")
print("=" * 50)

username = input("Enter username, example Ahmed: ").strip()
if not username:
    username = "Ahmed"

print("\nSelect role/profile:\n")

for i, profile in enumerate(profiles, start=1):
    print(f"{i}. {profile}")

while True:
    choice = input("\nEnter choice number: ").strip()

    if choice.isdigit():
        index = int(choice)
        if 1 <= index <= len(profiles):
            selected_role = profiles[index - 1]
            break

    print("Invalid choice. Try again.")

active_profile = {
    "user": username,
    "role": selected_role
}

with open("active_profile.json", "w", encoding="utf-8") as f:
    json.dump(active_profile, f, indent=4)

print("\nActive profile saved:")
print(json.dumps(active_profile, indent=4))
print("\nFile created: active_profile.json")