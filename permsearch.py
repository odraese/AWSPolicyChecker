import json

def readPolicy():
    ''' Reads the Policy JSON file, listing all the permissions that we currently
        request from the administrators. The returned map used the category (i.e.
        ec2) as key and a list of permissions as string list as values.
    '''
    policyMap = {}

    with open('policy.json') as perms:
        data = json.load(perms)

        statementArr = data['Statement']
        for stmt in statementArr:
            actionArr = stmt['Action']
            if isinstance(actionArr, str):
                actionArr = [actionArr]

            for action in actionArr:
                pair = action.split(':',2)

                if pair[0] in policyMap:
                    eventArr = policyMap[pair[0]]
                    if not pair[1] in eventArr:
                        eventArr.append(pair[1])
                else:
                    eventArr = [pair[1]]
                    policyMap[pair[0]] = eventArr

    return policyMap

def readEvents():
    ''' Reads and returns the set of disjunct permissions, found in the AWS event
        history of CloudTrail. Each key is a category (i.e. ec2) and the values
        is a sorted string list of permissions, found (as events) within that
        category.
    '''
    eventMap = {}

    with open('event_history.json') as events:
        data = json.load(events)
        records = data['Records']
        for event in records:
            eventSrc = event['eventSource'].split('.',2)[0]
            eventName = event['eventName']

            if eventSrc in eventMap:
                eventArr = eventMap[eventSrc]
                if not eventName in eventArr:
                    eventArr.append(eventName)
                    eventArr.sort()
            else:
                eventArr = [eventName]
                eventMap[eventSrc] = eventArr

    return eventMap

allPerms = readPolicy()
allEvents = readEvents()

# show missing permissions (not in policy)
print('********* Missing permissions ***********')
for category in allEvents:
    eventsInCategory = allEvents[category]

    print('Category {}:'.format(category))
    print('---------------------------------')
    if category in allPerms:
        permArr = allPerms[category]
        for e in eventsInCategory:
            if e not in permArr:
                print('{}:{}'.format(category, e))
    else:
        for e in eventsInCategory:
            print('{}:{}'.format(category, e))

    print()

# show unused permissions
print('********* Unused permissions ***********')
for category in allPerms:
    permArr = allPerms[category]

    if category in allEvents:
        theEvents = allEvents[category]
        for perm in permArr:
            if perm not in theEvents:
                print('{}.{}'.format(category, perm))
    else:
        print('-> Whole catagory {} unused!'.format(category));

