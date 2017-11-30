

class TestManager(object):

    def __init__(self):
        self.test_plans = dict()

    def get_test_plan(self, client_definition, listen_port):
        client_ip = client_definition[0]

        return self.__get_test_plan_for_ip("{}_{}".format(client_ip, listen_port))

    def __get_test_plan_for_ip(self, ip):
        """This method returns a data structure that maps
        all the available tests to their results if they were executed.
        """

        if ip not in self.test_plans.keys():
            self.test_plans[ip] = dict()
            
        return self.test_plans[ip]

    
            

    
        
