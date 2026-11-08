const assert = require('node:assert/strict');
const ELK = require('../frontend/vendor/elk.bundled.js');
const {arrange,metrics} = require('../frontend/model-layout.js');
const node = (id,i) => ({id,width:220,height:140+(i%3)*40,ports:[{column:'id',x:20,y:60},{column:'key',x:40,y:90}]});
const edge = (a,b,i) => ({id:`r${i}`,from_table:a,from_col:'id',to_table:b,to_col:'key'});
const fixtures = [
    ['star',10,Array.from({length:9},(_,i)=>[0,i+1])],
    ['shared dimensions',10,Array.from({length:8},(_,i)=>[i%2,i+2]).concat([[0,3],[1,4],[0,5],[1,6]])],
    ['cycles',8,[[0,1],[1,2],[2,3],[3,0],[2,4],[4,5],[5,2]]],
    ['parallel and disconnected',8,[[0,1],[0,1],[2,3],[3,4]]],
    ['dense model',24,Array.from({length:40},(_,i)=>[i%8,8+(i*7)%16])]
];
(async()=>{
    const elk=new ELK();
    let beforeTotal=0,afterTotal=0;
    for(const [name,count,pairs] of fixtures) {
        const input={nodes:Array.from({length:count},(_,i)=>node(`t${i}`,i)),edges:pairs.map(([a,b],i)=>edge(`t${a}`,`t${b}`,i))};
        const start=performance.now(), result=await arrange(input,elk);
        assert.equal(result.metrics.overlaps,0,name);
        assert.equal(result.metrics.intersections,0,name);
        assert.equal(result.routes.length,input.edges.length);
        result.routes.forEach(route=>route.points.slice(1).forEach((p,i)=>assert.ok(p.x===route.points[i].x||p.y===route.points[i].y,'orthogonal')));
        const repeated=await arrange(input,elk);
        assert.deepEqual(result,repeated,'deterministic');
        // Historical fixed-grid baseline with straight center-to-center edges.
        const baseline=input.nodes.map((n,i)=>({...n,x:40+i%3*300,y:40+Math.floor(i/3)*300}));
        const routes=input.edges.map(e=>{const a=baseline.find(n=>n.id===e.from_table),b=baseline.find(n=>n.id===e.to_table);return {...e,points:[{x:a.x+110,y:a.y+70},{x:b.x+110,y:b.y+70}]};});
        const previous=metrics(baseline,routes);
        beforeTotal+=previous.crossings;afterTotal+=result.metrics.crossings;
        console.log(name,JSON.stringify({baseline:previous,optimized:result.metrics,ms:Math.round(performance.now()-start)}));
    }
    assert.ok(afterTotal<beforeTotal,'aggregate crossings must improve over baseline');
    console.log(`PASS crossing total ${beforeTotal} -> ${afterTotal}`);
})().catch(error=>{console.error(error);process.exitCode=1;});
