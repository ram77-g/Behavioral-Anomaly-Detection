# ==========================================
# PHASE 1: FOUNDATION & SYNTHETIC DATA GEN (REALISM PASS)
# ==========================================
# This script generates realistic synthetic log data with proper behavioral noise,
# scaled attack classes for XGBoost balance, and causally accurate attack chains.

!pip install faker pandas numpy

import os
import json
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from faker import Faker

try:
    from google.colab import drive
    drive.mount('/content/drive')
    DATA_DIR = '/content/drive/MyDrive/Anomaly_Detection_Data'
except ImportError:
    DATA_DIR = './data'

os.makedirs(DATA_DIR, exist_ok=True)

class SyntheticDataGenerator:
    def __init__(self, num_users=500, num_devices=50, days=30):
        self.fake = Faker()
        self.num_users = num_users
        self.num_devices = num_devices
        self.days = days
        self.start_date = datetime.now() - timedelta(days=days)
        self.profiles = {}
        self.events = []
        
        self.resources = ['GitHub', 'Jira', 'Internal_Wiki', 'Payroll', 'AWS_Console', 'VPN', 'Production_DB']

    def generate_profiles(self):
        for _ in range(self.num_users):
            eid = f"U_{self.fake.uuid4()[:8]}"
            self.profiles[eid] = {
                'entity_type': 'user',
                'usual_hour': random.randint(8, 11),
                'usual_geo': self.fake.city(),
                'usual_ip_prefix': f"{random.randint(10, 192)}.{random.randint(0, 255)}",
                'usual_resources': random.sample(['GitHub', 'Jira', 'Internal_Wiki', 'VPN'], 2),
                'usual_device': {'os': random.choice(['Windows 10', 'macOS', 'Windows 11']), 'browser': 'Chrome'}
            }
            
        for _ in range(self.num_devices):
            eid = f"D_{self.fake.uuid4()[:8]}"
            self.profiles[eid] = {
                'entity_type': 'edge_device',
                'usual_hour': 0, # Runs 24/7
                'usual_geo': 'DataCenter-US',
                'usual_ip_prefix': "10.0",
                'usual_resources': ['Production_DB', 'AWS_Console'],
                'usual_device': {'os': 'Ubuntu 22.04', 'protocol': 'SSH'}
            }

    def _add_event(self, ts, eid, etype, ip, geo, res, auth, dur, cmds, dev, label):
        self.events.append({
            'entity_id': eid, 'entity_type': etype, 'timestamp': ts,
            'source_ip': ip, 'geo_location': geo, 'resource_accessed': res,
            'auth_method': auth, 'session_duration': dur,
            'command_sequence': json.dumps(cmds) if cmds else None,
            'device_fingerprint': json.dumps(dev) if dev else None,
            'label': label
        })

    def generate_normal_data(self):
        for day in range(self.days):
            current_date = self.start_date + timedelta(days=day)
            for eid, prof in self.profiles.items():
                # Base volume
                num_logins = random.randint(1, 5) if prof['entity_type'] == 'user' else random.randint(10, 20)
                
                for _ in range(num_logins):
                    # 10% Noise Factor: occasional late login, new IP, or unusual resource
                    is_noisy = random.random() < 0.10
                    
                    if is_noisy and prof['entity_type'] == 'user':
                        hour = random.randint(0, 23)
                        ip = f"{random.randint(1,255)}.{random.randint(1,255)}.x.x" # Mobile/Coffee shop IP
                        res = random.choice(self.resources)
                        geo = prof['usual_geo'] if random.random() < 0.8 else self.fake.city() # Occasional travel
                    else:
                        hour = int(np.random.normal(prof['usual_hour'], 1.5)) % 24 if prof['entity_type'] == 'user' else random.randint(0,23)
                        ip = f"{prof['usual_ip_prefix']}.{random.randint(0,255)}.{random.randint(0,255)}"
                        res = random.choice(prof['usual_resources'])
                        geo = prof['usual_geo']
                    
                    ts = current_date.replace(hour=hour, minute=random.randint(0,59), second=random.randint(0,59))
                    
                    self._add_event(
                        ts, eid, prof['entity_type'], ip, geo, res, 
                        'token' if prof['entity_type'] == 'user' else 'certificate',
                        abs(np.random.normal(120, 30)), [], prof['usual_device'], 'normal'
                    )

    def inject_attacks(self):
        users = [e for e, p in self.profiles.items() if p['entity_type'] == 'user']
        
        # 1. Brute Force (25 attacks * 30 failed attempts = 750 events)
        for _ in range(25):
            eid = random.choice(users)
            ts = self.start_date + timedelta(days=random.randint(5, 25), hours=random.randint(0,23))
            ip = self.fake.ipv4()
            for _ in range(30):
                self._add_event(ts, eid, 'user', ip, 'Unknown', 'VPN', 'password', 0.0, [], {}, 'brute_force')
                ts += timedelta(seconds=random.randint(1, 4))
            # Success
            self._add_event(ts, eid, 'user', ip, 'Unknown', 'VPN', 'password', 300.0, [], {}, 'brute_force')

        # 2. Impossible Travel (25 instances = 50 events)
        for _ in range(25):
            eid = random.choice(users)
            ts = self.start_date + timedelta(days=random.randint(5, 25))
            self._add_event(ts, eid, 'user', self.fake.ipv4(), 'New York', 'GitHub', 'token', 100, [], {}, 'impossible_travel')
            self._add_event(ts + timedelta(minutes=random.randint(15, 45)), eid, 'user', self.fake.ipv4(), 'Moscow', 'GitHub', 'token', 100, [], {}, 'impossible_travel')

        # 3. Credential Stuffing (5 attacks * 30 victims = 150 events)
        for _ in range(5):
            ts = self.start_date + timedelta(days=random.randint(5, 25))
            bad_ip = self.fake.ipv4()
            for victim in random.sample(users, 30):
                self._add_event(ts, victim, 'user', bad_ip, 'Unknown', 'VPN', 'password', 0.0, [], {}, 'credential_stuffing')
                ts += timedelta(seconds=random.randint(2, 6))

        # 4. Lateral Movement (25 instances = 50 events)
        for _ in range(25):
            eid = random.choice(users)
            ts = self.start_date + timedelta(days=random.randint(5, 25))
            ip = f"10.0.99.{random.randint(1,255)}" # Internal pivoted IP
            self._add_event(ts, eid, 'user', ip, self.profiles[eid]['usual_geo'], 'GitHub', 'token', 150, [], self.profiles[eid]['usual_device'], 'lateral_movement')
            ts += timedelta(minutes=random.randint(5, 20))
            self._add_event(ts, eid, 'user', ip, self.profiles[eid]['usual_geo'], 'AWS_Console', 'password', 500, ['assume_role', 'list_buckets'], self.profiles[eid]['usual_device'], 'lateral_movement')
            
        # 5. Device Spoofing (50 instances = 50 events)
        for _ in range(50):
            eid = random.choice(users)
            ts = self.start_date + timedelta(days=random.randint(5, 25))
            spoofed_device = {'os': 'Kali Linux', 'browser': 'curl'}
            self._add_event(ts, eid, 'user', self.fake.ipv4(), self.profiles[eid]['usual_geo'], 'Jira', 'token', 50, [], spoofed_device, 'device_spoofing')

        # 6. Low and Slow Exfiltration [NEW] (10 instances * 15 events = 150 events)
        for _ in range(10):
            eid = random.choice(users)
            base_ts = self.start_date + timedelta(days=random.randint(5, 20))
            for day_offset in range(3): # Over 3 days
                daily_ts = base_ts + timedelta(days=day_offset, hours=random.randint(1, 3))
                for access_num in range(5):
                    dur = 500 + (day_offset * 1000) + (access_num * 200) # Progressively longer
                    self._add_event(daily_ts, eid, 'user', self.profiles[eid]['usual_ip_prefix']+".99", self.profiles[eid]['usual_geo'], 'Production_DB', 'token', dur, ['SELECT * FROM customers'], self.profiles[eid]['usual_device'], 'low_and_slow')
                    daily_ts += timedelta(minutes=random.randint(30, 90))

        # 7. Attack Chain: Credential Compromise (30 instances = 90 events)
        for _ in range(30):
            eid = random.choice(users)
            base_ts = self.start_date + timedelta(days=random.randint(5, 25), hours=random.randint(0,23))
            bad_ip = self.fake.ipv4()
            bad_device = {'os': 'Windows 11', 'browser': 'Tor'}
            
            self._add_event(base_ts, eid, 'user', bad_ip, 'Remote_Geo', 'VPN', 'password', 10, [], bad_device, 'chain_credential_compromise')
            
            # Temporal Jitter: 5 to 60 mins gap
            step2_ts = base_ts + timedelta(minutes=random.randint(5, 60))
            self._add_event(step2_ts, eid, 'user', bad_ip, 'Remote_Geo', 'Account_Settings', 'password', 15, ['reset_password'], bad_device, 'chain_credential_compromise')
            
            # Temporal Jitter: 5 to 60 mins gap
            step3_ts = step2_ts + timedelta(minutes=random.randint(5, 60))
            self._add_event(step3_ts, eid, 'user', bad_ip, 'Remote_Geo', 'Payroll', 'password', 5000, ['export_all_data'], bad_device, 'chain_credential_compromise')

# 3. Generate & Save Data
print("Generating synthetic data profiles & normal events...")
generator = SyntheticDataGenerator(num_users=500, num_devices=50, days=30)
generator.generate_profiles()
generator.generate_normal_data()

print("Injecting complex attacks and attack chains...")
generator.inject_attacks()

# Convert events to DataFrame
df_events = pd.DataFrame(generator.events)
df_events = df_events.sort_values('timestamp').reset_index(drop=True)

# Prepare entities dataframe
entities_list = [{'entity_id': eid, 'entity_type': prof['entity_type'], 'profile_data': json.dumps(prof)} for eid, prof in generator.profiles.items()]
df_entities = pd.DataFrame(entities_list)

# Save
entities_path = os.path.join(DATA_DIR, 'entities.csv')
events_path = os.path.join(DATA_DIR, 'events.csv')
df_entities.to_csv(entities_path, index=False)
df_events.to_csv(events_path, index=False)

print("\n=== PHASE 1 COMPLETE (REALISM PASS) ===")
print(f"Total Entities: {len(df_entities)}")
print(f"Total Events: {len(df_events)}")
print("\nAnomaly Rate Distribution:")
print((df_events['label'].value_counts(normalize=True) * 100).round(3))
print("\nEvent Counts per Class:")
print(df_events['label'].value_counts())
