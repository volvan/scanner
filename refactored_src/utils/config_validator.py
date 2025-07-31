
##### MOVED FROM launch ip scan

# with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
#     tasks_remaining = rmq_conn.tasks_in_queue()

#     # If tasks are already in queue, stop the program # TODO: do we want that though
#     if tasks_remaining > 0:
#         logger.warning(f"[DiscoveryScanner] {tasks_remaining} tasks already in queue '{ALL_ADDR_QUEUE}'; skipping new enqueue.")
#         return
    

# if not PORTS_FILE:
#     logger.error("[PortScanner] Filename required to extract ports.")


# TODO:[Franz]  move this to the check thats in beginning ( serviceManager)
    # if not ALL_ADDR_QUEUE:
    #     raise ValueError("Queue name must be provided")


# TODO:[Franz]  move this to the check thats in beginning ( serviceManager)
    # else: # If not FETCH_RIX or TARGETS_FILE
    #     raise ValueError(
    #         "Either a filename, or fetch_rix=True must be provided."
    #     )
