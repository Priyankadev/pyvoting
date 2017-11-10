from apscheduler.schedulers.blocking import BlockingScheduler
# from auto_survey import post_survey

sched = BlockingScheduler()


@sched.scheduled_job('interval', minutes=5)
def timed_job():
    post_survey()
    print('This job is run every 5 minutes.')


sched.start()
