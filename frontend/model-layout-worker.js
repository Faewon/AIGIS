// The bundled engine chooses its in-process adapter when a document exists.
// It still executes entirely within this dedicated browser Worker.
self.document = {};
importScripts('/assets/vendor/elk.bundled.js', '/assets/model-layout.js');
const elk = new ELK();
self.onmessage = async ({data}) => {
    try { self.postMessage({id:data.id,result:await AigisModelLayout.arrange(data.input,elk)}); }
    catch(error) { self.postMessage({id:data.id,error:error.message || String(error)}); }
};
