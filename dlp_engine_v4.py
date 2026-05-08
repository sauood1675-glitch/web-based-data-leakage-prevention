from mitmproxy import http
import json
import os
import pandas as pd
import joblib

PROFILE_FILE = "active_profile.json"
KEYWORDS_FILE = "sensitive_keywords.json"

BEHAVIOR_SCORE_MODEL_FILE = "behavior_risk_model.pkl"
BEHAVIOR_SCORE_ENCODER_FILE = "behavior_score_encoders.pkl"

LOG_FILE = "decision_logs_v3.jsonl"

# Decision thresholds
RISK_ALLOW = 0.40
RISK_LOG = 0.55
RISK_WARN = 0.70


class DLPEngineV3:
    def __init__(self):
        self.active_profile = self.load_json(
            PROFILE_FILE,
            default={"user": "Unknown", "role": "Normal Employee"}
        )

        self.keyword_db = self.load_json(KEYWORDS_FILE, default={})

        self.behavior_score_model = None
        self.behavior_score_encoder = None
        self.behavior_features = None
        self.behavior_targets = None

        self.load_behavior_score_ai()

        print("=" * 110, flush=True)
        print("DLP ENGINE V3 STARTED - Score-Based Behavior AI Enabled", flush=True)
        print("=" * 110, flush=True)
        print(f"Active User              : {self.active_profile.get('user')}", flush=True)
        print(f"Active Role              : {self.active_profile.get('role')}", flush=True)
        print(f"Behavior Score Model     : {BEHAVIOR_SCORE_MODEL_FILE}", flush=True)
        print(f"Behavior Score Encoders  : {BEHAVIOR_SCORE_ENCODER_FILE}", flush=True)
        print(f"Keyword DB               : {KEYWORDS_FILE}", flush=True)
        print("=" * 110, flush=True)

    def load_json(self, path, default):
        if not os.path.exists(path):
            print(f"[DLP] WARNING: {path} not found. Using default.", flush=True)
            return default

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_behavior_score_ai(self):
        if not os.path.exists(BEHAVIOR_SCORE_MODEL_FILE):
            print(f"[DLP] ERROR: {BEHAVIOR_SCORE_MODEL_FILE} not found.", flush=True)
            return

        if not os.path.exists(BEHAVIOR_SCORE_ENCODER_FILE):
            print(f"[DLP] ERROR: {BEHAVIOR_SCORE_ENCODER_FILE} not found.", flush=True)
            return

        self.behavior_score_model = joblib.load(BEHAVIOR_SCORE_MODEL_FILE)
        encoders = joblib.load(BEHAVIOR_SCORE_ENCODER_FILE)

        self.behavior_score_encoder = encoders["onehot_encoder"]
        self.behavior_features = encoders["features"]
        self.behavior_targets = encoders["targets"]

        print("[DLP] Score-based Behavior AI loaded successfully.", flush=True)

    def save_log(self, record):
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def detect_action(self, flow):
        """
        Supports action simulation using query parameter:

        ?action=read
        ?action=download
        ?action=write_edit
        ?action=delete
        ?action=upload_share

        If no action parameter exists, it falls back to HTTP method.
        """

        query_action = flow.request.query.get("action", None)

        if query_action:
            action = query_action.lower().strip()

            if action == "write_edit":
                action = "write/edit"
            elif action == "upload_share":
                action = "upload/share"

            allowed = ["read", "write/edit", "delete", "download", "upload/share"]
            if action in allowed:
                return action

        method = flow.request.method.upper()

        if method == "GET":
            return "read"

        if method in ["POST", "PUT", "PATCH"]:
            return "write/edit"

        if method == "DELETE":
            return "delete"

        return "unknown"

    def clean_file_name(self, path):
        file_name = path.split("?")[0].strip("/")
        if not file_name:
            file_name = "dashboard.html"
        return file_name

    def count_keyword_hits(self, text, keywords):
        hits = []
        lower_text = text.lower()

        for keyword in keywords:
            keyword_lower = keyword.lower()
            if keyword_lower in lower_text:
                hits.append(keyword)

        return hits

    def sensitivity_to_score(self, level):
        mapping = {
            "NONE": 0.00,
            "LOW": 0.25,
            "MEDIUM": 0.50,
            "HIGH": 0.75,
            "CRITICAL": 1.00
        }
        return mapping.get(level.upper(), 0.00)

    def upgrade_sensitivity(self, base_level, critical_category_detected):
        """
        Many category words should not automatically make a file CRITICAL.
        Critical sensitivity is reserved for critical categories.
        """

        if critical_category_detected:
            return "CRITICAL"

        return base_level.upper()

    def analyze_content_sensitivity(self, content_text):
        """
        Content/Sensitivity Unit.

        Output:
        - category
        - sensitivity_level
        - content_risk_score
        - sensitive_words_found

        This unit does not allow or block.
        It only produces content-related scores.
        """

        category_scores = {}
        category_hits = {}

        for category, data in self.keyword_db.items():
            keywords = data.get("keywords", [])
            hits = self.count_keyword_hits(content_text, keywords)

            if hits:
                category_scores[category] = len(hits)
                category_hits[category] = hits

        if not category_scores:
            return {
                "category": "Unknown",
                "sensitivity_level": "NONE",
                "content_risk_score": 0.0,
                "sensitive_words_found": [],
                "category_confidence_score": 0.0
            }

        detected_category = max(category_scores, key=category_scores.get)
        detected_hits = category_hits[detected_category]

        total_hits = sum(category_scores.values())
        detected_hits_count = len(detected_hits)

        # Approximate category confidence from keyword dominance.
        category_confidence = detected_hits_count / max(total_hits, 1)
        category_confidence = round(min(max(category_confidence, 0.0), 1.0), 2)

        base_level = self.keyword_db[detected_category].get("base_sensitivity", "LOW")

        critical_categories = [
            "Credentials/Secrets",
            "Personal Information",
            "Customer Data"
        ]

        critical_detected = detected_category in critical_categories

        final_sensitivity = self.upgrade_sensitivity(
            base_level=base_level,
            critical_category_detected=critical_detected
        )

        content_score = self.sensitivity_to_score(final_sensitivity)

        # Small confidence boost only. This does not change sensitivity level.
        confidence_boost = min(total_hits * 0.01, 0.08)
        content_score = min(1.0, content_score + confidence_boost)

        all_hits = []
        for hits in category_hits.values():
            all_hits.extend(hits)

        return {
            "category": detected_category,
            "sensitivity_level": final_sensitivity,
            "content_risk_score": round(content_score, 2),
            "sensitive_words_found": sorted(list(set(all_hits))),
            "category_confidence_score": category_confidence
        }

    def action_risk_score(self, action):
        """
        Action risk is controlled by the DLP Engine, not by the AI.
        """

        mapping = {
            "read": 0.10,
            "download": 0.30,
            "write/edit": 0.45,
            "upload/share": 0.75,
            "delete": 0.90,
            "unknown": 0.50
        }

        return mapping.get(action, 0.50)

    def behavior_score_predict(self, role, action, category, sensitivity):
        """
        Behavior AI.

        Input:
        role + action + category + sensitivity

        Output:
        profile_match_score + behavior_risk_score

        This model does not decide ALLOW/BLOCK.
        """

        if self.behavior_score_model is None:
            return {
                "profile_match_score": 0.50,
                "behavior_risk_score": 0.50,
                "reason": "Behavior score model not loaded"
            }

        input_df = pd.DataFrame(
            [[role, action, category, sensitivity]],
            columns=self.behavior_features
        )

        encoded = self.behavior_score_encoder.transform(input_df)
        prediction = self.behavior_score_model.predict(encoded)[0]

        profile_match_score = float(prediction[0])
        behavior_risk_score = float(prediction[1])

        profile_match_score = round(min(max(profile_match_score, 0.0), 1.0), 2)
        behavior_risk_score = round(min(max(behavior_risk_score, 0.0), 1.0), 2)

        return {
            "profile_match_score": profile_match_score,
            "behavior_risk_score": behavior_risk_score,
            "reason": (
                f"Behavior AI score output: profile_match={profile_match_score}, "
                f"behavior_risk={behavior_risk_score}"
            )
        }

    def final_decision(self, content_risk, behavior_risk, action_risk):
        """
        Only the DLP Engine makes the decision.

        final_risk =
            content_risk  * 0.40
          + behavior_risk * 0.35
          + action_risk   * 0.25

        Decision thresholds:
            < 0.40 = ALLOW
            < 0.55 = LOG
            < 0.70 = WARN
            >=0.70 = BLOCK
        """

        final_risk = (
            content_risk * 0.40 +
            behavior_risk * 0.35 +
            action_risk * 0.25
        )

        final_risk = round(min(max(final_risk, 0.0), 1.0), 2)

        if final_risk < RISK_ALLOW:
            decision = "ALLOW"
        elif final_risk < RISK_LOG:
            decision = "LOG"
        elif final_risk < RISK_WARN:
            decision = "WARN"
        else:
            decision = "BLOCK"

        return final_risk, decision

    def print_table(self, record):
        print("\n" + "=" * 170, flush=True)
        print("DLP ENGINE V3 DECISION - AI SCORES + ENGINE EQUATION", flush=True)
        print("=" * 170, flush=True)

        headers = [
            "User",
            "Role",
            "Action",
            "File",
            "Category",
            "Sensitivity",
            "CatConf",
            "ProfileMatch",
            "ContentRisk",
            "BehaviorRisk",
            "ActionRisk",
            "FinalRisk",
            "Decision"
        ]

        values = [
            record["user"],
            record["role"],
            record["action"],
            record["file"],
            record["category"],
            record["sensitivity_level"],
            str(record["category_confidence_score"]),
            str(record["profile_match_score"]),
            str(record["content_risk_score"]),
            str(record["behavior_risk_score"]),
            str(record["action_risk_score"]),
            str(record["final_risk_score"]),
            record["decision"]
        ]

        widths = [10, 16, 14, 34, 24, 14, 8, 13, 12, 13, 11, 10, 10]

        fmt = ""
        for width in widths:
            fmt += "{:<" + str(width) + "} "

        print(fmt.format(*headers), flush=True)
        print("-" * 170, flush=True)
        print(fmt.format(*values), flush=True)

        print("\nSensitive Words Found:", flush=True)
        if record["sensitive_words_found"]:
            print(", ".join(record["sensitive_words_found"]), flush=True)
        else:
            print("None", flush=True)

        print("\nEquation:", flush=True)
        print(
            "final_risk = "
            "(content_risk * 0.40) + "
            "(behavior_risk * 0.35) + "
            "(action_risk * 0.25)",
            flush=True
        )

        print("\nReason:", flush=True)
        print(record["reason"], flush=True)

        print("=" * 170 + "\n", flush=True)

    def response(self, flow: http.HTTPFlow):
        # Analyze only PC 1 file server responses.
        if flow.request.host != "192.168.1.10":
            return

        if flow.request.port != 8000:
            return

        user = self.active_profile.get("user", "Unknown")
        role = self.active_profile.get("role", "Normal Employee")

        action = self.detect_action(flow)
        file_name = self.clean_file_name(flow.request.path)

        content_bytes = flow.response.content or b""

        try:
            content_text = content_bytes.decode("utf-8", errors="ignore")
        except Exception:
            content_text = ""

        sensitivity = self.analyze_content_sensitivity(content_text)

        behavior = self.behavior_score_predict(
            role=role,
            action=action,
            category=sensitivity["category"],
            sensitivity=sensitivity["sensitivity_level"]
        )

        action_risk = self.action_risk_score(action)

        final_risk, decision = self.final_decision(
            content_risk=sensitivity["content_risk_score"],
            behavior_risk=behavior["behavior_risk_score"],
            action_risk=action_risk
        )

        reason = (
            f"Sensitivity unit detected category '{sensitivity['category']}' "
            f"with sensitivity '{sensitivity['sensitivity_level']}' and "
            f"content risk {sensitivity['content_risk_score']}. "
            f"{behavior['reason']}. "
            f"The DLP Engine assigned action risk {action_risk} for action '{action}'. "
            f"The DLP Engine calculated final risk {final_risk} and selected decision '{decision}'."
        )

        record = {
            "user": user,
            "role": role,
            "action": action,
            "file": file_name,
            "category": sensitivity["category"],
            "sensitivity_level": sensitivity["sensitivity_level"],
            "category_confidence_score": sensitivity["category_confidence_score"],
            "sensitive_words_found": sensitivity["sensitive_words_found"],
            "profile_match_score": behavior["profile_match_score"],
            "content_risk_score": sensitivity["content_risk_score"],
            "behavior_risk_score": behavior["behavior_risk_score"],
            "action_risk_score": action_risk,
            "final_risk_score": final_risk,
            "decision": decision,
            "reason": reason
        }

        self.print_table(record)

        # ==========================================================
        # FINAL ENFORCEMENT POLICY - V3.1
        #
        # Important:
        # The AI models only provide scores.
        # The DLP Engine makes the final enforcement decision.
        #
        # Policy:
        # - BLOCK always blocks.
        # - WARN normally allows, except for dangerous actions.
        # - WARN + delete/upload-share is blocked.
        # - LOG and ALLOW pass through.
        # ==========================================================

        dangerous_actions = ["delete", "upload/share"]

        enforcement = "ALLOW"

        if decision == "BLOCK":
            enforcement = "BLOCK"

            flow.response = http.Response.make(
                403,
                (
                    "DLP BLOCKED\n\n"
                    "The DLP Engine blocked this action based on AI risk scores.\n"
                    f"Decision: {decision}\n"
                    f"Action: {action}\n"
                    f"Final Risk: {final_risk}\n"
                ).encode("utf-8"),
                {"Content-Type": "text/plain"}
            )

        elif decision == "WARN" and action in dangerous_actions:
            enforcement = "BLOCKED_BY_WARN_POLICY"

            flow.response = http.Response.make(
                403,
                (
                    "DLP WARNING - ACTION BLOCKED\n\n"
                    "This request received a WARN decision, but the requested action is dangerous.\n"
                    "The DLP Engine policy blocks WARN-level delete and upload/share actions.\n\n"
                    f"Decision: {decision}\n"
                    f"Action: {action}\n"
                    f"Final Risk: {final_risk}\n"
                ).encode("utf-8"),
                {"Content-Type": "text/plain"}
            )

        elif decision == "WARN":
            enforcement = "WARN_ALLOWED"

            # WARN for lower-risk actions is logged but allowed.
            pass

        elif decision == "LOG":
            enforcement = "LOG_ALLOWED"

            # LOG is silently allowed but recorded.
            pass

        elif decision == "ALLOW":
            enforcement = "ALLOW"

            # ALLOW is normal pass-through.
            pass

        record["enforcement"] = enforcement

        # Re-save the updated record with enforcement.
        self.save_log(record)


addons = [DLPEngineV3()]