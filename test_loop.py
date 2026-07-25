import asyncio
import phase4_backend

async def test_sim():
    # Only run for a few iterations
    phase4_backend.is_sim_running = True
    
    # We'll monkeypatch asyncio.sleep to break the loop after 10 iterations
    original_sleep = asyncio.sleep
    count = 0
    async def mock_sleep(seconds):
        nonlocal count
        count += 1
        if count >= 10:
            phase4_backend.is_sim_running = False
        await original_sleep(0.01) # fast
        
    asyncio.sleep = mock_sleep
    
    await phase4_backend.simulation_loop()
    print("Simulation loop finished successfully.")

asyncio.run(test_sim())
