"""Headless Edge usability smoke checks using the browser's DevTools protocol."""
import base64
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import urllib.request
from unittest.mock import patch

import uvicorn
import websocket


def run():
    from backend import server, database
    server.global_llm_engine.configure('heuristic')
    with tempfile.TemporaryDirectory(prefix='aigis_browser_') as directory, ExitStack() as stack:
        root = Path(directory)
        stack.enter_context(patch.dict(os.environ, {'AIGIS_RUN_DB': str(root / 'runs.db')}))
        for key, value in {'DATASETS_DIR': directory, 'UPLOADS_DIR': str(root / 'uploads'), 'DB_PATH': str(root / 'test.db'), 'ACTIVE_DB_PATH': str(root / 'test.db')}.items():
            stack.enter_context(patch.object(database, key, value))
        stack.enter_context(patch.object(server, 'BASE_DIR', directory))
        stack.enter_context(patch.object(server.stream_engine, 'db_path', database.DB_PATH))
        for agent in (server.global_fintech_sentinel, server.global_quant_investigator, server.global_secops_copilot):
            stack.enter_context(patch.object(agent, 'db_path', database.DB_PATH))
        http = uvicorn.Server(uvicorn.Config(server.app, host='127.0.0.1', port=18765, log_level='error'))
        thread = threading.Thread(target=http.run, daemon=True)
        thread.start()
        edge = None
        ws = None
        try:
            for _ in range(100):
                if http.started:
                    break
                time.sleep(.1)
            edge = subprocess.Popen([r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe', '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=19222', '--remote-allow-origins=http://localhost:19222', '--user-data-dir=' + str(root / 'browser'), 'about:blank'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pages = None
            for _ in range(100):
                try:
                    pages = json.load(urllib.request.urlopen('http://127.0.0.1:19222/json', timeout=1))
                    break
                except OSError:
                    time.sleep(.1)
            page = next(p for p in pages if p['type'] == 'page')
            ws = websocket.create_connection(page['webSocketDebuggerUrl'], timeout=20, suppress_origin=True)
            sequence = 0
            errors = []
            def command(method, params=None):
                nonlocal sequence
                sequence += 1
                request_id = sequence
                ws.send(json.dumps({'id': request_id, 'method': method, 'params': params or {}}))
                while True:
                    message = json.loads(ws.recv())
                    if message.get('method') in ('Runtime.exceptionThrown', 'Log.entryAdded'):
                        errors.append(message)
                    if message.get('id') == request_id:
                        return message.get('result', {})
            def evaluate(expression):
                result = command('Runtime.evaluate', {'expression': expression, 'awaitPromise': True, 'returnByValue': True})
                if 'exceptionDetails' in result:
                    print('EVALUATION ERROR', json.dumps(result['exceptionDetails']))
                return result.get('result', {}).get('value')
            command('Runtime.enable')
            command('Log.enable')
            command('Network.enable')
            command('Page.navigate', {'url': 'http://127.0.0.1:18765/'})
            command('Network.setExtraHTTPHeaders', {'headers': {}})
            time.sleep(3)
            print('INITIAL', json.dumps(evaluate('({ready:document.readyState, title:document.title, text:document.body.innerText.slice(-400), overflow:document.documentElement.scrollWidth>innerWidth})')))
            checks = [
                ('Settings', "document.querySelector('[data-handler-click][title]')"),
            ]
            print('PAGE VISIBILITY', evaluate("Array.from(document.querySelectorAll('[id^=pbi-page-]')).map(x=>[x.id,!x.classList.contains('hidden'),getComputedStyle(x).display])"))
            evaluate("window.alert = message => { window.lastAlert = message; }; window.confirm = () => true;")
            for view in ['data', 'model', 'sql', 'fyi', 'wargame']:
                evaluate(f"switchPowerBiView('{view}')")
                time.sleep(.3)
                print('VIEW', view, evaluate("Array.from(document.querySelectorAll('[id^=pbi-page-]')).filter(x=>getComputedStyle(x).display!=='none').map(x=>x.id)"))
            for name, op, close in [('PII','openPiiScannerModal','closePiiScannerModal'),('OpenAPI','openOpenApiModal','closeOpenApiModal'),('Risk','openFintechRiskModal','closeFintechRiskModal'),('Investigator','openQuantInvestigatorModal','closeQuantInvestigatorModal'),('Sentinel','openSentinelModal','closeSentinelModal')]:
                evaluate(op + '()')
                time.sleep(.4)
                print('MODAL', name, evaluate("Array.from(document.querySelectorAll('[id^=modal-]')).filter(x=>getComputedStyle(x).display!=='none').map(x=>x.id)"))
                evaluate(close + '()')
            evaluate("document.querySelector('[data-control-id=btn-db-dropdown]').click()")
            print('DROPDOWN', evaluate("Array.from(document.querySelectorAll('[data-control-id=db-dropdown-menu]')).map(x=>!x.classList.contains('hidden'))"))
            visible = evaluate("(()=>{const m=document.querySelector('[data-control-id=db-dropdown-menu]');const r=m.getBoundingClientRect();return m.contains(document.elementFromPoint(r.left+20,r.top+30));})()")
            print('DROPDOWN VISIBLE AND CLICKABLE', visible)
            if not visible:
                raise AssertionError('Database menu is clipped or covered')
            evaluate("document.body.click(); document.getElementById('rail-btn-data').click()")
            time.sleep(.5)
            print('RAIL CLICK', evaluate("!document.getElementById('pbi-page-data').classList.contains('hidden')"))
            evaluate("document.querySelector('[data-control-id=data-pane-search-input]').value='policy'; document.querySelector('[data-control-id=data-pane-search-input]').dispatchEvent(new Event('input',{bubbles:true}))")
            print('TABLE FILTER', evaluate("Array.from(document.querySelectorAll('#data-pane-tables-list > div')).filter(x=>!x.classList.contains('hidden')).map(x=>x.textContent.trim())"))
            evaluate("openOpenApiModal(); document.getElementById('openapi-input-content').value='invalid'; executeOpenApiParse()")
            time.sleep(.4)
            print('INVALID OPENAPI', evaluate("document.getElementById('openapi-endpoints-container').innerText"))
            evaluate("document.getElementById('openapi-input-content').value=JSON.stringify({info:{title:'Example',version:'1'},paths:{'/pay':{post:{summary:'Payment'}}}}); executeOpenApiParse()")
            time.sleep(.3)
            print('VALID OPENAPI', evaluate("document.getElementById('openapi-endpoints-container').innerText"))
            evaluate("closeOpenApiModal(); refreshInvestigatorUI({status:'UNSUPPORTED_DATASET',has_vulnerability:false,error:'Missing schema',root_cause_analysis:{rca_summary:'Missing schema'},sandbox_execution:{success:false,stderr:'Missing schema'}})")
            print('UNSUPPORTED LABEL', evaluate("document.getElementById('investigator-threat-badge').textContent"))
            # Exercise uploads through File + change event rather than a direct API call.
            evaluate("switchPowerBiView('data'); const transfer = new DataTransfer(); transfer.items.add(new File(['name,value\\nalpha,1\\nbeta,2\\n'],'browser.csv',{type:'text/csv'})); const upload=document.querySelector('[data-dashboard-controls=ribbon] input[type=file][accept=\".csv\"]'); upload.files=transfer.files; upload.dispatchEvent(new Event('change',{bubbles:true}));")
            time.sleep(1)
            print('CSV USER UPLOAD', evaluate("({alert:window.lastAlert,table:dataViewCurrentTable,tables:powerBiModelCache?.tables?.map(x=>x.name),status:document.querySelector('[data-dashboard-controls=ribbon] [data-control-id=dropdown-status-text]').innerText})"))
            print('CSV ROWS', evaluate("document.getElementById('data-view-tbody').innerText"))
            evaluate("openQuantInvestigatorModal()")
            time.sleep(.3)
            print('CSV INVESTIGATOR', evaluate("document.getElementById('investigator-threat-badge').textContent"))
            evaluate("closeQuantInvestigatorModal(); openFintechRiskModal(); document.getElementById('risk-input-velocity').value='1'; updateRiskSimulatorLive()")
            time.sleep(.3)
            print('RISK LOW', evaluate("document.getElementById('risk-calculated-score').innerText"))
            evaluate("document.getElementById('risk-input-velocity').value='20'; document.getElementById('risk-input-velocity').dispatchEvent(new Event('input',{bubbles:true}))")
            time.sleep(.3)
            print('RISK HIGH', evaluate("document.getElementById('risk-calculated-score').innerText"))
            evaluate("closeFintechRiskModal(); restoreDefaultTelemetryDb()")
            time.sleep(.5)
            print('RESTORE DEFAULT', evaluate("({alert:window.lastAlert,tables:powerBiModelCache?.tables?.map(x=>x.name)})"))
            print('MODAL BACKDROP CLICK', evaluate("openPiiScannerModal(); document.getElementById('modal-pii-scanner').click(); document.getElementById('modal-pii-scanner').classList.contains('hidden')"))
            evaluate("switchPowerBiView('sql'); document.getElementById('sql-query-input').value='SELECT COUNT(*) AS count FROM telemetry'; document.getElementById('btn-run-sql').click()")
            time.sleep(.4)
            print('SQL RESULT', evaluate("Array.from(document.querySelectorAll('[id*=sql]')).filter(x=>x.id.includes('result')).map(x=>[x.id,x.innerText.slice(0,300)])"))
            evaluate("openPiiScannerModal(); document.getElementById('pii-input-content').value='CMND: 123456789'; executePiiScan()")
            time.sleep(.3)
            print('PII RESULT', json.dumps(evaluate("document.getElementById('modal-pii-scanner').innerText.slice(-600)")))
            evaluate("closePiiScannerModal(); switchPowerBiView('data')")
            evaluate("document.getElementById('btn-run-wargame').focus(); openSecOpsWorkOrderModal()")
            time.sleep(.4)
            assert evaluate("document.getElementById('wo-kpi-gap').textContent === 'N/A'"), 'Missing measurement must stay unavailable'
            assert evaluate("document.getElementById('modal-secops-workorder').contains(document.activeElement)"), 'Modal must receive focus'
            evaluate("Array.from(document.querySelector('#modal-secops-workorder [role=dialog]').querySelectorAll('button:not(:disabled)')).at(-1).focus()")
            command('Input.dispatchKeyEvent', {'type':'keyDown','key':'Tab','code':'Tab','windowsVirtualKeyCode':9})
            assert evaluate("document.getElementById('modal-secops-workorder').contains(document.activeElement)"), 'Tab must remain inside the modal'
            evaluate("deploySecOpsWorkOrder()")
            time.sleep(.4)
            assert evaluate("document.getElementById('wo-status-badge').textContent === 'SIMULATED_ROLLOUT_PREVIEW'"), 'Preview must not claim production deployment'
            assert evaluate("document.getElementById('wo-canary-tbody').textContent.includes('SIMULATED_PENDING_APPROVAL')"), 'Stages must reflect backend status'
            command('Input.dispatchKeyEvent', {'type':'keyDown','key':'Escape','code':'Escape','windowsVirtualKeyCode':27})
            assert evaluate("document.getElementById('modal-secops-workorder').classList.contains('hidden')"), 'Escape must close work order'
            assert evaluate("document.activeElement.id === 'btn-run-wargame'"), 'Closing modal must restore focus'
            # Force out-of-order responses, even when the transport ignores abort.
            evaluate("""(async () => {
                const original = window.fetch;
                const pending = [];
                window.fetch = () => new Promise(resolve => pending.push(resolve));
                try {
                    const old = loadDataViewTable('old_table', 1);
                    const fresh = loadDataViewTable('fresh_table', 1);
                    const response = name => new Response(JSON.stringify({table_name:name,total_rows:0,columns:[],rows:[]}));
                    pending[1](response('fresh_table')); await fresh;
                    pending[0](response('old_table')); await old;
                    if (!document.getElementById('data-view-table-title').textContent.includes('fresh_table')) throw new Error('Stale table response overwrote current data');
                } finally { window.fetch = original; }
            })()""")
            # HTTP errors should surface, never be rendered as successful actions.
            assert evaluate("fetch('/api/v1/does-not-exist').then(() => false, error => error.message === 'Not Found')"), 'HTTP failures must reject'
            evaluate("openPiiScannerModal(); document.getElementById('pii-input-content').value='ordinary text'; executePiiScan()")
            time.sleep(.3)
            assert evaluate("document.getElementById('pii-results-container')?.textContent.includes('not a compliance assessment') || document.getElementById('modal-pii-scanner').textContent.includes('not a compliance assessment')"), 'Clean scan must not claim compliance'
            evaluate("closePiiScannerModal(); switchPowerBiView('data')")
            print('IMPROVEMENTS: work-order evidence, modal focus/Escape, HTTP errors, stale-response guard, and PII copy passed')
            # Real browser verification of the wargame workflow and stale-result clearing.
            evaluate("switchPowerBiView('wargame'); tweakConfig.adversarialRounds=2; tweakConfig.burstStreams=3; const previousNotify=notify; notify=(message,type)=>{window.lastNotification=message;previousNotify(message,type)}")
            evaluate('runFullWargame()')
            assert evaluate("document.getElementById('wargame-assessment').textContent.includes('PASSED IN MOCK')"), str(evaluate("({error:window.lastNotification,assessment:document.getElementById('wargame-assessment').textContent,evidence:document.getElementById('wargame-evidence').textContent,log:document.getElementById('logs-verification').textContent})"))
            assert evaluate("document.getElementById('wargame-evidence').textContent.includes('Baseline illegal:')"), 'Evidence must expose measured baseline'
            evaluate('loadWargameHistory()')
            assert evaluate("document.getElementById('wargame-history').textContent.includes('COMPLETED')"), 'History must show completed runs'
            evaluate('runMultiCycleStressRecheck(5)')
            assert evaluate("document.getElementById('wargame-assessment').textContent.includes('CYCLE CHECK PASSED')"), 'Five cycle recheck must be scoped'
            evaluate('runMultiCycleStressRecheck(10)')
            assert evaluate("document.getElementById('wargame-assessment').textContent.includes('CYCLE CHECK PASSED')"), 'Ten cycle recheck must be scoped'
            evaluate('resetSimulation()')
            assert evaluate("document.getElementById('wargame-assessment').textContent === 'NOT ASSESSED'"), 'Reset must clear verification'
            evaluate("(async () => { tweakConfig.adversarialRounds=1; await runStage3(); await runStage4(); await runStage5(); await runStage6(); })()")
            assert evaluate("document.getElementById('wargame-assessment').textContent.includes('PASSED IN MOCK')"), 'Single-stage workflow must render verified evidence'
            evaluate("""(async () => {
                const original = window.fetch;
                window.fetch = async () => { throw new Error('Injected browser network failure'); };
                try { await runStage5(); } catch (_) {} finally { window.fetch = original; }
            })()""")
            assert evaluate("document.getElementById('wargame-assessment').textContent.includes('INCONCLUSIVE') && document.getElementById('retest-mitigation').textContent==='N/A'"), 'Request failure must clear previous green results'
            print('WARGAME: full run, stages, 5/10 cycles, history, reset and network failure passed')
            evaluate('startDurableBenchmark()')
            assert evaluate("document.getElementById('wargame-job-status').textContent.includes('COMPLETED')"), 'Durable benchmark must complete through polling'
            evaluate('loadTemporalShadow()')
            assert evaluate("document.getElementById('temporal-shadow-results').textContent.includes('SHADOW ONLY')"), 'Shadow signals must be explicitly non-enforcing'
            print('DURABLE JOB + SHADOW: browser polling and read-only signal inspection passed')
            evaluate("document.getElementById('postgres-profile').value='AIGIS_POSTGRES_UNCONFIGURED_BROWSER_CHECK'; discoverPostgresSource()")
            assert evaluate("!document.getElementById('postgres-discover').disabled && document.getElementById('postgres-snapshot').disabled"), 'Failed PostgreSQL discovery must leave retry enabled and import disabled'
            assert evaluate("document.getElementById('postgres-source-status').textContent.includes('Invalid or unavailable')"), 'Unconfigured PostgreSQL profile must fail safely'
            print('POSTGRES UI: unconfigured profile fails safely without replacing the dataset')
            import sys
            if '--wargame-only' in sys.argv:
                return
            evaluate("switchPowerBiView('model')")
            evaluate("document.getElementById('model-properties').scrollIntoView({block:'center',inline:'nearest'})")
            time.sleep(.3)
            print('MODEL GEOMETRY', json.dumps(evaluate("""(() => {
                const ids=['cell0-model-view','model-canvas-wrapper','model-zoom-container','model-nodes-container','model-properties'];
                return ids.map(id=>{const el=document.getElementById(id), r=el.getBoundingClientRect(), s=getComputedStyle(el); return {id,x:r.x,y:r.y,w:r.width,h:r.height,overflow:s.overflow,origin:s.transformOrigin,position:s.position};});
            })()""")))
            assert evaluate("getComputedStyle(document.getElementById('model-canvas-wrapper')).overflow === 'auto'"), 'Canvas must clip and scroll cards'
            assert evaluate("getComputedStyle(document.getElementById('model-zoom-container')).transformOrigin === '0px 0px'"), 'Zoom must use top-left coordinates'
            assert evaluate("""(() => {
                const pane=document.getElementById('model-properties'), r=pane.getBoundingClientRect();
                const x=Math.max(0,r.left)+15;
                const top=Math.max(0,r.top), bottom=Math.min(window.innerHeight,r.bottom);
                return bottom>top && pane.contains(document.elementFromPoint(x,(top+bottom)/2));
            })()"""), 'Cards must not paint over properties'
            assert evaluate("document.querySelectorAll('.model-column').length > 29"), 'Model must expose all columns'
            point = evaluate("(() => {const header=document.querySelector('.model-table-header'); header.scrollIntoView({block:'center',inline:'center'}); const box=header.getBoundingClientRect(); return {x:box.left+40,y:box.top+12,old:powerBiModelCache.tables[0].x};})()")
            command('Input.dispatchMouseEvent', {'type':'mousePressed','x':point['x'],'y':point['y'],'button':'left','clickCount':1})
            command('Input.dispatchMouseEvent', {'type':'mouseMoved','x':point['x']+70,'y':point['y']+30,'button':'left','buttons':1})
            command('Input.dispatchMouseEvent', {'type':'mouseReleased','x':point['x']+70,'y':point['y']+30,'button':'left','clickCount':1})
            assert evaluate(f"powerBiModelCache.tables[0].x > {point['old']}"), 'Dragging header must move table'
            evaluate("""(() => {
                const select = (table, col) => Array.from(document.querySelectorAll('.model-column')).find(el => el.dataset.modelTable === table && el.dataset.modelCol === col);
                select('telemetry', 'user_id').click();
                select('incident_memory', 'incident_id').click();
                document.getElementById('model-cardinality').value = '*:1';
                saveModelRelationship();
            })()""")
            assert evaluate("powerBiModelCache.relationships.some(r => r.from_col === 'user_id' && r.to_col === 'incident_id' && r.cardinality === '*:1')"), 'Column connection must be saved'
            assert evaluate("document.getElementById('model-svg-layer').querySelectorAll('path[role=button]').length > 0"), 'Relationship must render as interactive connector'
            evaluate("document.querySelector('#model-svg-layer path[role=button]').dispatchEvent(new MouseEvent('click', {bubbles:true}))")
            assert evaluate("document.getElementById('modal-model-relationship').classList.contains('hidden') === false"), 'Existing editor remains open during this test'
            evaluate("document.getElementById('modal-model-relationship').classList.add('hidden'); document.querySelector('#model-svg-layer path[role=button]').dispatchEvent(new MouseEvent('click', {bubbles:true}))")
            assert evaluate("document.getElementById('modal-model-relationship').classList.contains('hidden') && document.getElementById('model-properties-content').textContent.includes('Cardinality')"), 'Single click must inspect without opening editor'
            evaluate("selectModelTable('telemetry'); showRelatedModelTables(); fitModelToView()")
            assert evaluate("document.querySelectorAll('[data-model-card]').length === 2 && Number.isFinite(modelZoomScale)"), 'Related layout must show connected tables and fit canvas'
            evaluate("document.querySelector('#model-layout-tabs button').click()")
            assert evaluate("document.querySelectorAll('[data-model-card]').length === 3"), 'All tables restores full canvas'
            evaluate("(async()=>{await autoArrangeModel();})()")
            print('LAYOUT WORKER', evaluate("({routes:modelRoutes.size,hint:document.getElementById('model-hint').textContent,notification:document.getElementById('aigis-notifications')?.textContent})"))
            assert evaluate("modelRoutes.size === 1 && !document.getElementById('model-undo-button').disabled"), 'Worker must return column routes and enable undo'
            evaluate("undoModelArrange()")
            assert evaluate("document.getElementById('model-undo-button').disabled"), 'Undo must restore positions'
            evaluate("saveModelRelationship(); document.getElementById('modal-model-relationship').classList.add('hidden'); powerBiModelCache=null; initPowerBiModelView()")
            time.sleep(.4)
            assert evaluate("powerBiModelCache.relationships.some(r => r.cardinality === '*:1')"), 'Relationship must survive metadata reload'
            evaluate("openModelRelationshipEditor(powerBiModelCache.relationships[0]); document.getElementById('model-relation-active').value='false'; saveModelRelationship()")
            assert evaluate("powerBiModelCache.relationships[0].active === false"), 'Relationship editing must persist inactive status'
            evaluate("document.querySelector('#model-relationship-list button[aria-label]').click()")
            assert evaluate("powerBiModelCache.relationships.length === 0"), 'Delete must remove the relationship'
            evaluate("document.getElementById('modal-model-relationship').classList.add('hidden'); switchPowerBiView('data')")
            print('MODEL: column connection, interactive connector, editing, persistence, deletion passed')
            for width in (1440, 1024, 768, 390):
                command('Emulation.setDeviceMetricsOverride', {'width':width,'height':1000,'deviceScaleFactor':1,'mobile':False})
                evaluate("(async()=>{switchPowerBiView('model'); await initPowerBiModelView(); await autoArrangeModel(); fitModelToView();})()")
                time.sleep(.15)
                geometry = evaluate("""(() => {
                    const canvas=document.getElementById('model-canvas-wrapper'), pane=document.getElementById('model-properties');
                    const a=canvas.getBoundingClientRect(), b=pane.getBoundingClientRect();
                    const cards=Array.from(document.querySelectorAll('[data-model-card]')).map(el=>el.getBoundingClientRect());
                    return {width:innerWidth,canvasWidth:a.width,canvas:{x:a.x,y:a.y,w:a.width,h:a.height},cards:cards.map(r=>({x:r.x,y:r.y,w:r.width,h:r.height})),paneSeparated:a.right<=b.left+1 || a.bottom<=b.top+1,
                        cardsFit:cards.every(r=>r.left>=a.left-1 && r.right<=a.right+1 && r.top>=a.top-1 && r.bottom<=a.bottom+1),
                        overlaps:cards.some((r,i)=>cards.slice(i+1).some(s=>r.left<s.right && r.right>s.left && r.top<s.bottom && r.bottom>s.top))};
                })()""")
                print('MODEL RESPONSIVE', geometry)
                assert geometry['canvasWidth'] > 150 and geometry['paneSeparated'] and geometry['cardsFit'] and not geometry['overlaps'], 'Model cards must fit without overlapping chrome or each other'
            evaluate("switchPowerBiView('data')")
            command('Emulation.setDeviceMetricsOverride', {'width':390,'height':844,'deviceScaleFactor':1,'mobile':True})
            time.sleep(.2)
            print('MOBILE', evaluate("({viewport:innerWidth,content:document.documentElement.scrollWidth,overflow:document.documentElement.scrollWidth>innerWidth})"))
            print('ERRORS', json.dumps(errors, indent=2))
            if any(error.get('method') == 'Runtime.exceptionThrown' for error in errors):
                raise AssertionError('Browser reported JavaScript exceptions')
            command('Browser.close')
        finally:
            if ws:
                ws.close()
            if edge:
                try:
                    edge.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    edge.terminate()
                    edge.wait(timeout=10)
            http.should_exit = True
            thread.join(timeout=10)


if __name__ == '__main__':
    run()
