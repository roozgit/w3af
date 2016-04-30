"""
xss2.py

This file is part of w3af, http://w3af.org/ .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""
import w3af.core.controllers.output_manager as om
import w3af.core.data.kb.knowledge_base as kb
import w3af.core.data.constants.severity as severity
import gtk
import webkit
import gobject
import time
import thread
import re

from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
from w3af.core.controllers.csp.utils import site_protected_against_xss_by_csp

from w3af.core.data.kb.vuln import Vuln
from w3af.core.data.db.disk_list import DiskList
from w3af.core.data.fuzzer.fuzzer import create_mutants
from w3af.core.data.fuzzer.utils import rand_alnum
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList
from w3af.core.data.context.context.main import get_context_iter
from w3af.core.data.context.context.main import get_context
from w3af.core.data.context.context.html import *
from w3af.core.data.parsers.document_parser import DocumentParser
from collections import namedtuple
from w3af.core.controllers.w3afCore import w3afCore


RANDOMIZE = 'RANDOMIZE'
JSCODE = 'console.log(424242)'
#JSCODE = 'alert(424242)'

JS_EVENTS = ['onload', 'onerror', 'onunload', 'onsubmit', 'onclick', 'ondblclick', 'onmousedown', 'onmousemove',
             'onmouseout', 'onmouseover', 'onmouseup', 'onchange', 'onfocus',
             'onblur', 'onscroll', 'onselect', 'onkeydown', 'onkeypress', 'onkeyup']

#PRECISE_PAYLOAD entries are currently based on test cases. To populate this table comprehensively, much more testing with various browsers is needed
PRECISE_PAYLOAD = {HtmlAttrNoQuote : ["PAYLOAD'onerror=JSCODE ", "PAYLOAD'onload=JSCODE ", "PAYLOAD'onunload=JSCODE ","PAYLOAD'onclick=JSCODE ",
                                      'PAYLOAD onload=JSCODE ','PAYLOAD onerror=JSCODE ', 'onunload=JSCODE ', 'PAYLOAD onclick=JSCODE '],
                   HtmlAttrBackticks:[''],
                   HtmlAttrDoubleQuote:['"><script>JSCODE</script>', '%34><script>JSCODE</script>', '"onclick=JSCODE attrib',"'onerror=JSCODE attrib","'onclick=JSCODE attrib"],
                   HtmlAttrSingleQuote:["'><script>JSCODE</script>", '%27><script>JSCODE</script>','"onclick=JSCODE attrib',"'onerror=JSCODE attrib","'onclick=JSCODE attrib"],
                   HtmlProcessingInstruction:[''],
                   HtmlDeclaration:[''],
                   CSSText:[''],
                   ScriptText:['"%3bJSCODE//','%27%3bJSCODE//'],
                   HtmlAttr:[''],
                   HtmlComment:[''],
                   HtmlText:['<script>JSCODE</script>'],
                   HtmlTag:[''],
                   HtmlTagClose:['']}

class xss2(AuditPlugin):
    """
    Identify cross site scripting vulnerabilities
    AND
    try to find a precise payload and verify it!
    
    :author: Roozbeh Khodadadeh (rkhodada@asu.edu)
    """

    ESCAPES = [
        # Start a new tag
        '<',

        # Escape HTML comments
        '-->',

        # Escape JavaScript multi line and CSS comments
        '*/',

        # Escapes for CSS
        '*/:("\'',

        # The ":" is useful in cases where we want to add the javascript
        # protocol like <a href="PAYLOAD">   -->   <a href="javascript:alert()">
        ':',

        # Escape single line comments in JavaScript
        "\n",

        # Escape the HTML attribute value string delimiter
        '"',
        "'",
        "`",
        "' ",
        '" ',

        # Escape HTML attribute values without string delimiters
        " ="
    ]

    PAYLOADS = ['%s%s%s' % (RANDOMIZE, p, RANDOMIZE) for p in ESCAPES]

    
    def __init__(self):
        AuditPlugin.__init__(self)
        self.discovered=0
        self.generic=True
        self._xss_mutants = DiskList(table_prefix='xss')        

        # User configured parameters. I didn't touch this so the framework doesn't break. But my program
        #doesn't use persistent xss check.
        #In principle precise payload algorithm can work for persistent XSS too.
        self._check_persistent_xss = False

    def audit(self, freq, orig_response):
        """
        Tests an URL for XSS vulnerabilities.
        
        :param freq: A FuzzableRequest
       
        """
        fake_mutants = create_mutants(freq, [''])
        
        vuln=None
        for fake_mutant in fake_mutants:
            self._check_xss_in_parameter(fake_mutant)

        #Added by me! If there are no mutants, then try and send payloads in fragment section of the URL
        if len(fake_mutants)==0:
            self.start_browser()
            vuln= self.try_hash(freq)
            self.quit_browser()
        if vuln:
            self._report_vuln(None, None, vuln)

        
    def start_browser(self):
        """
        Starts headless browser in a thread-safe way (almost!)
        """
        
        gtk.gdk.threads_init()
        thread.start_new_thread(gtk.main, ())

    def quit_browser(self):
        """
        Stops all gtk threads. Because of unknown bugs/issues, a lot of times, I had to manually
        kill python processes. A quit wrapper is needed to ensure that gtk threads are terminated
        in any case
        """
        asynchronous_gtk_message(gtk.main_quit)()
            
    def try_hash(self,freq):
        """
        Tries to send payloads in fragment part of the URL.
        It then uses webkit to analyze the results and find a precise payload
        Also see: https://code.google.com/archive/p/pywebkitgtk/wikis/HowDoI.wiki
        webkitgtk doesn't have a get_body() method. So a Javascript hack is used.
        """
        
        url_str = freq.get_url().url_string
        xssRands = [(replace_randomize(i),i[9:-9]) for i in self.PAYLOADS]
        pe_list=[]
        for payload in xssRands:
            view = synchronous_gtk_message(webkit.WebView)()
            funview=synchronous_gtk_message(self.open_fetch)(view,url_str+"#"+payload[0])
            agm=asynchronous_gtk_message(funview.execute_script)
            agm('oldtitle=document.title;document.title=document.documentElement.innerHTML;')
            body = synchronous_gtk_message(funview.get_title)()
            pe=synchronous_gtk_message(self.process_result)(body,payload)

            #if payload is in body, try to exploit!
            if pe:
                #Again, this list is not complete, other HtmlAttrs may be added for more meaningful exploits
                if isinstance(pe[1],HtmlAttrDoubleQuote):
                    precise_list = PRECISE_PAYLOAD[HtmlAttrDoubleQuote]
                    for pcsp in precise_list:
                        view2= synchronous_gtk_message(webkit.WebView)()
                        synchronous_gtk_message(view2.connect)('console-message',self._javascript_console_message)
                        synchronous_gtk_message(view2.connect)('load-finished', self._javascript_finished_loading)
                        synchronous_gtk_message(self.open_fetch)(view2,url_str+"#"+pcsp.replace('JSCODE',JSCODE))
                        synchronous_gtk_message(view2.connect)('console-message',self._javascript_console_message)
                        synchronous_gtk_message(view2.connect)('load-finished', self._javascript_finished_loading)
                        if not self.generic: break
                    return pcsp.replace('JSCODE',JSCODE)
                                    
        return None
            
    def open_fetch(self,view, uris):
        """
        fetches a url in webkit
        """
        
        view.load_uri(uris)
        return view

    def process_result(self, body, payload):
        """
        Analyzes the resuls of page load and sends the resuls back to program
        """
        
        body_lower = body.lower()
        rand_str = payload[0].split(payload[1])[0]
        final_payload=payload[0]
        if not payload[0] in body_lower and rand_str in body_lower:
            #We probably have encoding or javascript code is changing the type of quotes used in payload
            #It mostly happens when Javascript causes browsers to change ' with "!
            ind_list=[]
            for m in re.finditer(rand_str, body_lower):
                ind_list.append(m.start())
                
            replaced_with= body_lower[5+ind_list[0]:ind_list[1]]
            if len(payload[1])==len(replaced_with):
                final_payload= payload[0].replace(payload[1],replaced_with)

        #After manipulating payload a little, it is found again!
        if final_payload in body_lower:
            for context in get_context_iter(body_lower, final_payload):
                if context.can_break():
                    rep_start_index=0
                    for occurence in re.finditer(rand_str, final_payload):
                        rep_start_index=occurence.start()
                    return (final_payload[0:rep_start_index] + final_payload[rep_start_index:].replace(rand_str,'XSS_CODE'),context)
        return None

    def find_precise_payloads(self,initial_payload,precise_mutant_list):
        """
        Sends precise payloads from the PRECISE_PAYLOAD dictionary one by one
        Analyzes the results and executes Javascript to see if a console message with content 424242
        has been logged or not.
        If there is no console message, then it returns its best guess (based on what w3af's xss finder has already found)
        """
        for mutant in precise_mutant_list:
            mutant.set_token_value(mutant.get_token_value().replace('JSCODE',JSCODE))
            view = synchronous_gtk_message(webkit.WebView)()
            synchronous_gtk_message(view.connect)('script-alert', self._javascript_alert_message)
            synchronous_gtk_message(view.connect)('console-message',self._javascript_console_message)
            synchronous_gtk_message(view.connect)('load-finished', self._javascript_finished_loading)
            url = synchronous_gtk_message(mutant.get_fuzzable_request)()
            url = synchronous_gtk_message(url.get_uri)()
            url= url.url_string
            synchronous_gtk_message(self.open_fetch)(view,url)
            synchronous_gtk_message(view.connect)('script-alert', self._javascript_alert_message)
            synchronous_gtk_message(view.connect)('console-message',self._javascript_console_message)
            synchronous_gtk_message(view.connect)('load-finished', self._javascript_finished_loading)
            
            if not self.generic:
                break;
        if not self.generic:
            return True,mutant.get_token_value()
        self.generic=False
        return False,mutant.get_token_value()

    #Hooks to catch browser events. For example we don't want an alert box to suddenly pop up!
    #Also console messages are caught, so we know that our exploit has worked
    def _javascript_finished_loading(self, view, frame):
        pass

    def _javascript_alert_message(self, view, frame, message):
        return True  #True prevents calling original handler

    def _javascript_console_message(self, view, message,line,sourceid):
        self.generic=False
        return True  #True prevents calling original handler

    
    def _check_xss_in_parameter(self, mutant):
        """
        Tries to identify (persistent) XSS in one parameter. (This is from w3af)
        """
        #if not self._identify_trivial_xss(mutant):
        self._search_xss(mutant)
        

    def _report_vuln(self, mutant, response, mod_value):
        """
        Create a Vuln object and store it in the KB. (From w3af framework)
        
        :return: None
        """
        csp_protects = site_protected_against_xss_by_csp(response)
        vuln_severity = severity.LOW if csp_protects else severity.MEDIUM
        
        desc = 'A Cross Site Scripting vulnerability was found at: %s'
        desc %= mutant.found_at()
        if self.discovered==0:
            desc += "No console message could be produced. The result may need slight modifications to work in actual browser"
        
        if csp_protects:
            desc += ('The risk associated with this vulnerability was lowered'
                     ' because the site correctly implements CSP. The'
                     ' vulnerability is still a risk for the application since'
                     ' only the latest versions of some browsers implement CSP'
                     ' checking.')
        
        v = Vuln.from_mutant('Cross site scripting vulnerability', desc,
                             vuln_severity, response.id, self.get_name(),
                             mutant)
        v.add_to_highlight(mod_value) 
        
        self.kb_append_uniq(self, 'xss', v)

    def _search_xss(self, mutant):
        """
        Analyze the mutant for reflected XSS.
        
        @parameter mutant: A mutant that was used to test if the parameter
                           was echoed back or not
        """
        xss_strings = [replace_randomize(i) for i in self.PAYLOADS]
        fuzzable_params = [mutant.get_token_name()]

        mutant_list = create_mutants(mutant.get_fuzzable_request(),
                                     xss_strings,
                                     fuzzable_param_list=fuzzable_params)

        self.start_browser()
        #Because of all the problems with threads, I don't send the mutants in threads!
        #Instead I open up a browser and try to find a precise payload more synchronously
        #self._send_mutants_in_threads(self._uri_opener.send_mutant,mutant_list,self._analyze_echo_result)
        
        for mutant in mutant_list:
            self._analyze_echo_result(mutant,self._uri_opener.send_mutant(mutant))
            if not self.generic:
                break
        self.quit_browser()
        
    def _analyze_echo_result(self, mutant, response):
        """
        Do we have a reflected XSS?
        
        :return: None, record all the results in the kb.
        """
        #Persistent XSS has been commented out. I am not using it.
        # Add data for the persistent xss checking
        #if self._check_persistent_xss:
        #    self._xss_mutants.append((mutant, response.id))

        with self._plugin_lock:
            
            if self._has_bug(mutant):
                return
            
            sent_payload = mutant.get_token_payload()
            body_lower = response.get_body().lower()
            sent_payload_lower = sent_payload.lower()
            precise_payloads=[]
            for context in get_context_iter(body_lower, sent_payload_lower):
                if context.is_executable() or context.can_break():
                    #Ok. Framework is on to something. Let's find the prices payload"
                    #executable context means a js event. So we can just inject our code directly
                    if context.is_executable():
                        precise_payloads=['JSCODE']
                    if ':' in sent_payload_lower:
                        precise_payloads=['javascript:JSCODE']
                    if isinstance(context, HtmlText):
                        precise_payloads = PRECISE_PAYLOAD[HtmlText]
                    if isinstance(context, HtmlAttrDoubleQuote):
                        precise_payloads = PRECISE_PAYLOAD[HtmlAttrDoubleQuote]
                    if isinstance(context,ScriptText):
                        precise_payloads = PRECISE_PAYLOAD[ScriptText]
                    if isinstance(context,HtmlAttrSingleQuote):
                        precise_payloads = PRECISE_PAYLOAD[HtmlAttrSingleQuote]
                    if isinstance(context, HtmlAttrNoQuote):
                        precise_payloads = PRECISE_PAYLOAD[HtmlAttrNoQuote]
                    #The list of checks for precise payloads can be improved. Currently it passes the test cases (thanks God!)
                    if precise_payloads:
                        fuzzable_params = [mutant.get_token_name()]
                        precise_mutant_list = create_mutants(mutant.get_fuzzable_request(),
                                     precise_payloads,
                                     fuzzable_param_list=fuzzable_params)
                        fpr = self.find_precise_payloads(sent_payload_lower, precise_mutant_list)
                        
                        #If we have verified the payload, report it differently
                        if fpr[0]:
                            mutant.set_token_value(fpr[1])
                            self.discovered+=1
                            print fpr[1]
                            self._report_vuln(mutant, response, fpr[1])
                            return
                        else:
                            mutant.set_token_value(fpr[1])
                            print fpr[1]
                            self._report_vuln(mutant, response, fpr[1])
                            self.generic=False
                            return
                    return

    def end(self):
        """
        This method is called when the plugin wont be used anymore. (BY w3af framework)
        """
        if self._check_persistent_xss:
            self._identify_persistent_xss()
        
        self._xss_mutants.cleanup()

 
    def set_options(self, options_list):
        """
        This method sets all the options that are configured using the user
        interface generated by the framework using the result of get_options().
        
        :param options_list: A dictionary with the options for the plugin.
        :return: No value is returned.
        """
        self._check_persistent_xss = False #options_list['persistent_xss'].get_value()
        
    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return """
        This plugin tries to find exact and precise xss payloads
        
        """

#helper method to create randomized payloads
def replace_randomize(data):
    rand_str = rand_alnum(5).lower()
    return data.replace(RANDOMIZE, rand_str)

#helper method to create gtk message
def synchronous_gtk_message(fun):

    class NoResult: pass

    def worker((R, function, args, kwargs)):
        R.result = apply(function, args, kwargs)

    def fun2(*args, **kwargs):
        class R: result = NoResult
        gobject.idle_add(worker, (R, fun, args, kwargs))
        while R.result is NoResult: time.sleep(0.04)
        return R.result

    return fun2

#helper method to create gtk message
def asynchronous_gtk_message(fun):

    def worker((function, args, kwargs)):
        apply(function, args, kwargs)

    def fun2(*args, **kwargs):
        gobject.idle_add(worker, (fun, args, kwargs))

    return fun2
