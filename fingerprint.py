#!/usr/bin/env python3

import os
import json

class KnowledgeBase(object):
    

    def classify(self, results):

        classification = {
            "firefox": 0,
            "edge": 0,
            "chrome": 0,
            "safari": 0
        }

        
        if 'test_case1' in results.keys():
            classification = self.analyze_testcase1(classification, results['test_case1'])
        if 'test_case2' in results.keys():
            classification = self.analyze_testcase2(classification, results['test_case2'])
        if 'test_case3' in results.keys():
            classification = self.analyze_testcase3(classification, results['test_case3'])
        if 'test_case5' in results.keys():
            classification = self.analyze_testcase5(classification, results['test_case5'])
        if 'test_case7' in results.keys():
            classification = self.analyze_testcase7(classification, results['test_case7'])
        if 'testcase_9' in results.keys():
            classification = self.analyze_testcase9(classification, results['test_case9'])
        if 'testcase_12' in results.keys():
            classification = self.analyze_testcase12(classification, results['test_case12'])
        if 'testcase_13' in results.keys():
            classification = self.analyze_testcase13(classification, results['test_case13'])
        if 'testcase_15' in results.keys():
            classification = self.analyze_testcase15(classification, results['test_case15'])
        if 'testcase_17' in results.keys():
            classification = self.analyze_testcase17(classification, results['test_case17'])
        if 'testcase_19' in results.keys():
            classification = self.analyze_testcase19(classification, results['test_case19'])

        scores = dict()

        families = ['safari', 'chrome', 'edge', 'firefox']


        total = 0
        for f in families:
            total += classification[f]

        if total == 0:
            return {}
        factor = 100.0 / float(total)

        for f in families:
            scores[f] = round(classification[f] * factor, 2)
            
        return {"summary": scores, "details": classification}

    def analyze_testcase19(self, classification, responses):

        for i_response, response in enumerate(responses):
            print(response)

            
    def analyze_testcase17(self, classification, responses):

        for i_response, response in enumerate(responses):
            if i_response == 2:
                symbol_names = self.get_symbol_names(response)

                if symbol_names == ['SETTINGS', 'RST_STREAM', 'HEADERS', 'WINDOW_UPDATE']:
                    classification = self.add_classes(classification, ["firefox", "firefox_52.0.1", "firefox_53.0"])
                elif symbol_names == ['SETTINGS']:
                    classification = self.add_classes(classification, ["firefox", "firefox_45.9.0", "edge", "edge_38.14393.8066.0", "safari", "safari_10.1.1", "chrome", "chrome_58.0.3029.110", "chromium", "chromium_58.0.3029.110", "chrome_57.0.2987.133", "chrome_59.0.3071.86"])
                

        return classification
            
            
    def analyze_testcase15(self, classification, responses):

        for i_response, response in enumerate(responses):
            if i_response == 7:
                symbol_names = self.get_symbol_names(response)

                if symbol_names == ['GOAWAY']:
                    classification = self.add_classes(classification, ["safari", "safari_10.1.1"])
                elif symbol_names == ['SETTINGS']:
                    classification = self.add_classes(classification, ["chrome", "chrome_58.0.3029.110", "chromium", "chromium_58.0.3029.110", "chrome_57.0.2987.133", "chrome_59.0.3071.86", "firefox", "firefox_45.9.0", "firefox_52.0.1", "firefox_53.0"])
                elif len(symbol_names) == 0:
                    classification = self.add_classes(classification, ["edge", "edge_38.14393.8066.0"])                    
                    

        return classification


    def analyze_testcase13(self, classification, responses):

        for i_response, response in enumerate(responses):

            if i_response == 4:
                symbol_names = self.get_symbol_names(response)
                if len(symbol_names) == 0:
                    classification = self.add_classes(classification, ["edge", "edge_38.14393.8066.0"])
                elif symbol_names == ['SETTINGS', 'RST_STREAM', 'HEADERS', 'WINDOW_UPDATE']:
                    classification = self.add_classes(classification, ["firefox", "firefox_45.9.0", "firefox_52.0.1", "firefox_53.0"])
                elif symbol_names == ['SETTINGS']:
                    classification = self.add_classes(classification, ["chrome", "chrome_58.0.3029.110", "chromium", "chromium_58.0.3029.110", "chrome_57.0.2987.133", "chrome_59.0.3071.86", "safari", "safari_10.1.1"])

        return classification
            
    def analyze_testcase12(self, classification, responses):

        for i_response, response in enumerate(responses):
            if i_response == 2:                
                symbol_names = self.get_symbol_names(response)
                
                if symbol_names == ['SETTINGS', 'RST_STREAM', 'HEADERS', 'WINDOW_UPDATE']:
                    classification = self.add_classes(classification, ["firefox", "firefox_45.9.0", "firefox_52.0.1", "firefox_53.0"])
        return classification

    def analyze_testcase9(self, classification, responses):

        for i_response, response in enumerate(responses):
            if i_response == 2:
                symbol_names = self.get_symbol_names(response)
                if symbol_names == ['RST_STREAM', 'HEADERS', 'WINDOW_UPDATE']:
                    classification = self.add_classes(classification, ["firefox", "firefox_45.9.0", "firefox_52.0.1", "firefox_53.0"])

        return classification
            
    def analyze_testcase7(self, classification, responses):

        for i_response, response in enumerate(responses):
            if i_response == 2:
                symbol_names = self.get_symbol_names(response)
                if len(symbol_names) == 0:
                    classification = self.add_classes(classification, ["edge", "edge_38.14393.8066.0"])
                else:
                    symbol_attributes = self.get_symbol_attributes(response)

                    atts =  symbol_attributes[0]
                    if 'Additional Debug Data' in atts.keys():
                        if 'PRIORITY: stream_id == 0' in atts['Additional Debug Data']:
                            classification = self.add_classes(classification, ["safari", "safari_10.1.1"])
                        elif 'Framer' in atts['Additional Debug Data']:
                            classification = self.add_classes(classification, ["chrome", "chrome_58.0.3029.110", "chromium", "chromium_58.0.3029.110", "chrome_57.0.2987.133", "chrome_59.0.3071.86"])
                        elif atts['Additional Debug Data'] == "b''":
                            classification = self.add_classes(classification, ["firefox", "firefox_45.9.0", "firefox_52.0.1", "firefox_53.0"])

        return classification
            
    def analyze_testcase5(self, classification, responses):

        for i_response, response in enumerate(responses):
            if i_response == 2:
                symbol_names = self.get_symbol_names(response)

                if symbol_names == ['GOAWAY']:
                    classification = self.add_classes(classification, ["chrome", "chrome_58.0.3029.110", "chromium", "chromium_58.0.3029.110", "chrome_57.0.2987.133", "chrome_59.0.3071.86"])
                elif symbol_names == ['RST_STREAM', 'HEADERS', 'WINDOW_UPDATE']:
                    classification = self.add_classes(classification, ["firefox", "firefox_45.9.0", "firefox_52.0.1", "firefox_53.0"])

                elif len(symbol_names) == 0:
                    classification = self.add_classes(classification, ["safari", "safari_10.1.1", "edge", "edge_38.14393.8066.0"])


        return classification

    def analyze_testcase3(self, classification, responses):

        for i_response, response in enumerate(responses):
            if i_response == 1:
                if len(response) == 0:
                    classification = self.add_classes(classification, ["edge", "edge_38.14393.8066.0"])
                else:
                    symbol_attributes = self.get_symbol_attributes(response)
                    
                    if 'Additional Debug Data' in symbol_attributes[0].keys() and 'Framer' in symbol_attributes[0]['Additional Debug Data']:
                        classification = self.add_classes(classification, ["chrome", "chrome_58.0.3029.110", "chromium", "chromium_58.0.3029.110", "chrome_57.0.2987.133", "chrome_59.0.3071.86"])
                    elif 'Additional Debug Data' in symbol_attributes[0].keys() and 'SETTINGS: stream_id != 0' in symbol_attributes[0]['Additional Debug Data']:
                        classification = self.add_classes(classification, ["safari", "safari_10.1.1"])

                    elif 'Additional Debug Data' in symbol_attributes[0].keys() and symbol_attributes[0]['Additional Debug Data'] == "b''":
                        classification = self.add_classes(classification, ["firefox", "firefox_45.9.0", "firefox_52.0.1", "firefox_53.0"])
        
        return classification

    def analyze_testcase2(self, classification, responses):

        for i_response, response in enumerate(responses):
            if i_response == 1:
                if len(response) == 0:
                    classification = self.add_classes(classification, ["edge", "edge_38.14393.8066.0"])
        
        return classification
        

    def analyze_testcase1(self, classification, responses):

        for i_response, response in enumerate(responses):
            if i_response == 0:
                # compare symbol names
                symbol_names = self.get_symbol_names(response)
                if symbol_names == ['SETTINGS', 'WINDOW_UPDATE', 'PRIORITY', 'PRIORITY', 'PRIORITY', 'PRIORITY', 'PRIORITY', 'HEADERS', 'WINDOW_UPDATE']:
                    classification = self.add_classes(classification, ["firefox", "firefox_52.0.1", "firefox_53.0", "firefox_45.9.0"])
                elif symbol_names == ['SETTINGS', 'WINDOW_UPDATE', 'HEADERS']:
                    classification = self.add_classes(classification, ["edge", "edge_38.14393.8066.0", "chromium", "chromium_58.0.3029.110", "chrome", "chrome_58.0.3029.110", "chrome_57.0.2987.133", "chrome_59.0.3071.86", "safari", "safari_10.1.1"])

                    # compare symbol attributes
                    symbol_attributes = self.get_symbol_attributes(response)
                    if 'SETTINGS_HEADER_TABLE_SIZE' in symbol_attributes[0].keys():
                        if symbol_attributes[0]['SETTINGS_HEADER_TABLE_SIZE'] == 65536:
                            classification = self.add_classes(classification, ["chrome", "chrome_58.0.3029.110", "chromium", "chromium_58.0.3029.110", "chrome_57.0.2987.133", "chrome_59.0.3071.86"])

                    if 'SETTINGS_INITIAL_WINDOW_SIZE' in symbol_attributes[0].keys():
                        if symbol_attributes[0]['SETTINGS_INITIAL_WINDOW_SIZE'] == 10485760:
                            classification = self.add_classes(classification, ["edge", "edge_38.14393.8066.0"])

                        elif symbol_attributes[0]['SETTINGS_INITIAL_WINDOW_SIZE'] == 65535:
                            classification = self.add_classes(classification, ["safari", "safari_10.1.1"])
                        elif symbol_attributes[0]['SETTINGS_INITIAL_WINDOW_SIZE'] == 6291456:
                            classification = self.add_classes(classification, ["chrome", "chrome_58.0.3029.110", "chromium", "chromium_58.0.3029.110", "chrome_57.0.2987.133", "chrome_59.0.3071.86"])
                        else:
                            print(symbol_attributes[0]['SETTINGS_INITIAL_WINDOW_SIZE'])
                else:
                    print("===>", symbol_names)

            elif i_response == 1:

                symbol_names = self.get_symbol_names(response)
                symbol_attributes = self.get_symbol_attributes(response)

                # compare symbol names
                if symbol_names == ['GOAWAY']:
                    classification = self.add_classes(classification, ["safari", "safari_10.1.1", "firefox", "firefox_45.9.0", "firefox_52.0.1", "firefox_53.0"])

                    if 'Additional Debug Data' in symbol_attributes[0] and "SETTINGS expected" in symbol_attributes[0]['Additional Debug Data']:
                        classification = self.add_classes(classification, ["safari", "safari_10.1.1"])
                    elif 'Additional Debug Data' in symbol_attributes[0] and symbol_attributes[0]['Additional Debug Data'] == "b''":
                        classification = self.add_classes(classification, ["firefox", "firefox_45.9.0", "firefox_52.0.1", "firefox_53.0"])
                    
                elif symbol_names == ['PING']:
                    classification = self.add_classes(classification, ["chrome", "chrome_58.0.3029.110", "chrome_57.0.2987.133", "chrome_59.0.3071.86", "edge", "edge_38.14393.8066.0", "chromium", "chromium_58.0.3029.110"])

        return classification

    def add_classes(self, classification, browsers):
        for browser in browsers:
            if browser not in classification.keys():
                classification[browser] = 0

            classification[browser] += 1

        return classification
    
    def get_symbol_names(self, response):
        clean = []

        for symbol_name, symbol_attrs in response:
            clean.append(symbol_name)
        

        return clean

    def get_symbol_attributes(self, response):
        clean = []

        for symbol_name, symbol_attrs in response:
            clean.append(symbol_attrs)
        

        return clean

    

def main():
    base = "results/"

    kbase = KnowledgeBase()
    
    for f in os.listdir(base):
        browser = f.replace(".json", "")
        with open(os.path.join(base, f), "r") as fd:
            classification = kbase.classify(json.load(fd))
            

        print(browser, classification)


            
if __name__ == "__main__":
    main()
    
