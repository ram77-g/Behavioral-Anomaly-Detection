import phase4_backend
from datetime import datetime

phase4_backend.init_live_engine()

def test_sim():
    now = datetime.now()
    found_chain = False
    
    for i in range(200):
        new_events = phase4_backend.live_generator.generate_live_events(num_events=1, current_timestamp=now)
        for _, row in new_events.iterrows():
            if row['label'] == 'chain_credential_compromise':
                print(f"Found chain event: {row['resource_accessed']} at {row['timestamp']}")
                found_chain = True
                
    if found_chain:
        print("SUCCESS: Found chained events across ticks.")
    else:
        print("FAILED: No chain found.")

test_sim()
