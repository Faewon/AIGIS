/* Shared by the layout Worker and offline graph fixtures. */
(function(root) {
    'use strict';
    const key = (table, column, side) => JSON.stringify([table, column, side]);
    function metrics(nodes, routes) {
        let overlaps=0, intersections=0, crossings=0, sharedLength=0, length=0;
        nodes.forEach((a,i)=>nodes.slice(i+1).forEach(b=>{
            if(a.x<b.x+b.width && a.x+a.width>b.x && a.y<b.y+b.height && a.y+a.height>b.y) overlaps++;
        }));
        const lines=routes.flatMap(r=>r.points.slice(1).map((b,i)=>({a:r.points[i],b,route:r}))).filter(s=>Math.hypot(s.b.x-s.a.x,s.b.y-s.a.y)>.001);
        const cross=(a,b,c)=>(b.x-a.x)*(c.y-a.y)-(b.y-a.y)*(c.x-a.x);
        lines.forEach((s,i)=>{
            length+=Math.hypot(s.b.x-s.a.x,s.b.y-s.a.y);
            nodes.forEach(n=>{
                if(n.id===s.route.from_table || n.id===s.route.to_table) return;
                let lo=0,hi=1,hit=true;
                const dx=s.b.x-s.a.x,dy=s.b.y-s.a.y;
                const p=[-dx,dx,-dy,dy],q=[s.a.x-n.x-1,n.x+n.width-1-s.a.x,s.a.y-n.y-1,n.y+n.height-1-s.a.y];
                for(let k=0;k<4;k++) {
                    if(p[k]===0) {if(q[k]<0) hit=false;}
                    else if(p[k]<0) lo=Math.max(lo,q[k]/p[k]);
                    else hi=Math.min(hi,q[k]/p[k]);
                }
                if(hit && lo<hi) intersections++;
            });
            lines.slice(i+1).forEach(t=>{
                if(s.route.id===t.route.id) return;
                if(cross(s.a,s.b,t.a)*cross(s.a,s.b,t.b)<0 && cross(t.a,t.b,s.a)*cross(t.a,t.b,s.b)<0) crossings++;
                if(Math.abs(cross(s.a,s.b,t.a))<.001 && Math.abs(cross(s.a,s.b,t.b))<.001) {
                    const axis=Math.abs(s.a.x-s.b.x)>.001?'x':'y';
                    sharedLength+=Math.max(0,Math.min(Math.max(s.a[axis],s.b[axis]),Math.max(t.a[axis],t.b[axis]))-Math.max(Math.min(s.a[axis],s.b[axis]),Math.min(t.a[axis],t.b[axis])));
                }
            });
        });
        const width=Math.max(0,...nodes.map(n=>n.x+n.width)),height=Math.max(0,...nodes.map(n=>n.y+n.height));
        return {overlaps,intersections,crossings,sharedLength:Math.round(sharedLength),length:Math.round(length),bends:routes.reduce((sum,r)=>sum+Math.max(0,r.points.length-2),0),area:width*height};
    }
    function better(a,b) {
        if(!b) return true;
        for(const key of ['overlaps','intersections','crossings','sharedLength','length','bends','area']) if(a[key]!==b[key]) return a[key]<b[key];
        return false;
    }
    function graph(input,direction,seed) {
        const outgoing=direction==='RIGHT'?'EAST':'WEST',incoming=direction==='RIGHT'?'WEST':'EAST';
        return {id:'model',layoutOptions:{
            'elk.algorithm':'layered','elk.direction':direction,'elk.edgeRouting':'ORTHOGONAL',
            'elk.randomSeed':String(seed),'elk.padding':'[top=40,left=40,bottom=40,right=40]',
            'elk.layered.crossingMinimization.strategy':'LAYER_SWEEP',
            'elk.layered.crossingMinimization.greedySwitch.type':'TWO_SIDED',
            'elk.spacing.nodeNode':'40','elk.layered.spacing.nodeNodeBetweenLayers':'100',
            'elk.spacing.edgeNode':'20','elk.spacing.edgeEdge':'14','elk.separateConnectedComponents':'true'
        },children:input.nodes.map(n=>({id:n.id,width:n.width,height:n.height,
            layoutOptions:{'elk.portConstraints':'FIXED_POS'},
            ports:n.ports.flatMap(p=>[outgoing,incoming].map(side=>({id:key(n.id,p.column,side),width:0,height:0,
                x:side==='EAST'?n.width:0,y:p.y,
                layoutOptions:{'elk.port.side':side}})))
        })),edges:input.edges.map(e=>({id:e.id,sources:[key(e.from_table,e.from_col,outgoing)],targets:[key(e.to_table,e.to_col,incoming)]}))};
    }
    async function arrange(input,elk) {
        let best=null;
        // Keep ports on the field's left/right edge in every candidate.
        for(const [direction,seed] of [['RIGHT',1],['RIGHT',7],['LEFT',1],['LEFT',7]]) {
            const result=await elk.layout(graph(input,direction,seed));
            const nodes=result.children.map(n=>({id:n.id,x:n.x,y:n.y,width:n.width,height:n.height}));
            const routes=result.edges.map(edge=>{
                const section=edge.sections?.[0];
                if(!section) throw new Error('Layout engine returned an unrouted relationship.');
                return {...input.edges.find(e=>e.id===edge.id),points:[section.startPoint,...(section.bendPoints||[]),section.endPoint]};
            });
            const quality=metrics(nodes,routes);
            if(better(quality,best?.metrics)) best={nodes,routes,metrics:quality,direction,seed};
        }
        return best;
    }
    const api={arrange,metrics,better};
    if(typeof module!=='undefined' && module.exports) module.exports=api;
    else root.AigisModelLayout=api;
})(typeof self!=='undefined'?self:globalThis);
