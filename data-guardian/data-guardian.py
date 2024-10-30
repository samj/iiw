import json
from pathlib import Path
import logging
from datetime import datetime, timedelta
import openai
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Verify environment variables are loaded
logging.info(f"Using Azure OpenAI Deployment: {os.getenv('AZURE_OPENAI_DEPLOYMENT')}")
logging.info(f"Using Azure OpenAI Endpoint: {os.getenv('AZURE_OPENAI_ENDPOINT')}")
logging.info(f"Using Azure OpenAI API Version: {os.getenv('AZURE_OPENAI_API_VERSION')}")

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DataGuardian:
    def __init__(self, config_file: str = 'config.json'):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.decisions = []
        self.decisions_path = Path('access_decisions.json')
        self.client = openai.AzureOpenAI(
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
            api_key=os.getenv("AZURE_OPENAI_KEY"),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION")
        )

    def get_policy_decision(self, scenario: dict) -> dict:
        """Get AI-generated policy decision for any scenario."""
        system_prompt = """
        You are a data access policy expert. Evaluate the given scenario and determine:
        1. If access should be granted based on:
           - Legitimacy of the request
           - Appropriateness of the requester role
           - Sensitivity of requested data
           - Context and purpose alignment
           - Privacy and security implications
        
        2. For each requested data item, determine if it is:
           - ALLOWED: Appropriate for the context and role
           - DENIED: Inappropriate, excessive, or violates privacy
        
        3. If any access is permitted, define appropriate policy rules including:
           - Access duration (in minutes)
           - Required credentials
           - Purpose limitations
           - Any additional restrictions
        
        Return your decision as a JSON object with:
        {
            "access_permitted": boolean,
            "data_decisions": {
                "allowed_data": [list of allowed data items],
                "denied_data": [list of denied data items]
            },
            "policy": {
                "access_duration": int,
                "required_credentials": [string],
                "purpose_limitation": string
            },
            "reasoning": {
                "general_assessment": string,
                "allowed_explanation": string,
                "denied_explanation": string
            }
        }
        """

        user_prompt = f"""
        Evaluate this scenario:
        Context: {json.dumps(scenario['context'], indent=2)}
        Data Requested: {json.dumps(scenario['data_requested'], indent=2)}
        """

        response = self.client.chat.completions.create(
            model=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"}
        )

        return json.loads(response.choices[0].message.content)

    def evaluate_access_request(self, scenario_name: str, credentials: dict) -> dict:
        """Evaluate an access request for any scenario."""
        if scenario_name not in self.config['scenarios']:
            raise ValueError(f"Unknown scenario: {scenario_name}")

        scenario = self.config['scenarios'][scenario_name]
        policy_decision = self.get_policy_decision(scenario)

        decision = {
            'scenario': scenario_name,
            'context': scenario['context'],
            'timestamp': datetime.now().isoformat(),
            'access_granted': policy_decision['access_permitted'],
            'data_decisions': policy_decision['data_decisions'],
            'reasoning': policy_decision['reasoning']
        }

        if policy_decision['access_permitted']:
            # Verify credentials against AI-determined policy
            policy = policy_decision['policy']
            required_credentials = set(policy['required_credentials'])
            provided_credentials = set(credentials.keys())

            if not required_credentials.issubset(provided_credentials):
                decision['access_granted'] = False
                decision['reasoning']['general_assessment'] = f"Missing required credentials: {required_credentials - provided_credentials}"
            else:
                decision['policy'] = policy
                decision['credentials_verified'] = True

        self.decisions.append(decision)
        return decision

    def save_decisions(self):
        """Save all decisions to a JSON file."""
        with open(self.decisions_path, 'w') as f:
            json.dump(self.decisions, f, indent=2)

    def get_access_history(self) -> list:
        """Return the history of access decisions."""
        return self.decisions

def main():
    guardian = DataGuardian()
    
    # Test scenarios with appropriate credentials
    test_scenarios = {
        # Fully legitimate scenarios
        'routine_checkup': {'medical_license': 'ML123456'},
        'tax_preparation': {'cpa_license': 'CPA789012'},
        
        # Completely inappropriate scenarios
        'celebrity_data_breach': {'press_id': 'PRESS345678'},
        'corporate_espionage': {'employee_id': 'EMP901234'},
        
        # Mixed scenarios
        'school_nurse': {'nurse_license': 'RN567890'},
        'fitness_trainer': {'trainer_certification': 'PT234567'},
        'restaurant_reservation': {'employee_id': 'REST789012'}
    }

    # Process each scenario and group results
    results = {
        'fully_approved': [],
        'fully_denied': [],
        'partial_access': []
    }

    for scenario_name, creds in test_scenarios.items():
        decision = guardian.evaluate_access_request(scenario_name, creds)
        
        # Categorize the decision
        if decision['access_granted'] and not decision['data_decisions']['denied_data']:
            results['fully_approved'].append(scenario_name)
        elif not decision['access_granted']:
            results['fully_denied'].append(scenario_name)
        else:
            results['partial_access'].append(scenario_name)
            
        # Log detailed decision
        logging.info(f"\n{'='*50}")
        logging.info(f"SCENARIO: {scenario_name}")
        logging.info(f"{'='*50}")
        logging.info(f"ACCESS GRANTED: {decision['access_granted']}")
        logging.info("\nALLOWED DATA:")
        for data in decision['data_decisions']['allowed_data']:
            logging.info(f"- {data}")
        logging.info("\nDENIED DATA:")
        for data in decision['data_decisions']['denied_data']:
            logging.info(f"- {data}")
        logging.info("\nREASONING:")
        logging.info(f"General: {decision['reasoning']['general_assessment']}")
        if decision['access_granted']:
            logging.info("\nPOLICY:")
            logging.info(json.dumps(decision['policy'], indent=2))

    # Log summary
    logging.info("\n\nSUMMARY OF DECISIONS")
    logging.info("===================")
    logging.info(f"\nFully Approved Scenarios: {len(results['fully_approved'])}")
    for scenario in results['fully_approved']:
        logging.info(f"- {scenario}")
    
    logging.info(f"\nFully Denied Scenarios: {len(results['fully_denied'])}")
    for scenario in results['fully_denied']:
        logging.info(f"- {scenario}")
    
    logging.info(f"\nPartial Access Scenarios: {len(results['partial_access'])}")
    for scenario in results['partial_access']:
        logging.info(f"- {scenario}")

    # Save all decisions to file
    guardian.save_decisions()
    logging.info(f"\nAll decisions have been saved to {guardian.decisions_path}")

if __name__ == "__main__":
    main()
    