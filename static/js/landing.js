// landing.js - Particles background and counter animations

document.addEventListener('DOMContentLoaded', () => {
    // 1. Canvas Network Nodes Animation
    const canvas = document.getElementById('networkCanvas');
    if (canvas) {
        const ctx = canvas.getContext('2d');
        
        let width = canvas.width = window.innerWidth;
        let height = canvas.height = window.innerHeight;
        
        window.addEventListener('resize', () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        });
        
        const numNodes = Math.min(Math.floor((width * height) / 18000), 100);
        const nodes = [];
        
        // Node class
        class Node {
            constructor() {
                this.x = Math.random() * width;
                this.y = Math.random() * height;
                this.vx = (Math.random() - 0.5) * 0.4;
                this.vy = (Math.random() - 0.5) * 0.4;
                this.radius = Math.random() * 2 + 1;
            }
            
            update() {
                this.x += this.vx;
                this.y += this.vy;
                
                // Boundary collision
                if (this.x < 0 || this.x > width) this.vx *= -1;
                if (this.y < 0 || this.y > height) this.vy *= -1;
            }
            
            draw() {
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                ctx.fillStyle = '#06b6d4';
                ctx.fill();
            }
        }
        
        // Instantiate nodes
        for (let i = 0; i < numNodes; i++) {
            nodes.push(new Node());
        }
        
        // Track mouse
        let mouse = { x: null, y: null, maxDist: 120 };
        window.addEventListener('mousemove', (e) => {
            mouse.x = e.clientX;
            mouse.y = e.clientY;
        });
        window.addEventListener('mouseleave', () => {
            mouse.x = null;
            mouse.y = null;
        });
        
        function animate() {
            ctx.clearRect(0, 0, width, height);
            
            // Update and draw nodes
            nodes.forEach(node => {
                node.update();
                node.draw();
            });
            
            // Draw connections
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    const dx = nodes[i].x - nodes[j].x;
                    const dy = nodes[i].y - nodes[j].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    
                    if (dist < 100) {
                        ctx.beginPath();
                        ctx.moveTo(nodes[i].x, nodes[i].y);
                        ctx.lineTo(nodes[j].x, nodes[j].y);
                        
                        const alpha = (1 - dist / 100) * 0.15;
                        ctx.strokeStyle = `rgba(6, 182, 212, ${alpha})`;
                        ctx.lineWidth = 0.8;
                        ctx.stroke();
                    }
                }
                
                // Connection to mouse
                if (mouse.x !== null && mouse.y !== null) {
                    const mdx = nodes[i].x - mouse.x;
                    const mdy = nodes[i].y - mouse.y;
                    const mdist = Math.sqrt(mdx * mdx + mdy * mdy);
                    
                    if (mdist < mouse.maxDist) {
                        ctx.beginPath();
                        ctx.moveTo(nodes[i].x, nodes[i].y);
                        ctx.lineTo(mouse.x, mouse.y);
                        
                        const alpha = (1 - mdist / mouse.maxDist) * 0.25;
                        ctx.strokeStyle = `rgba(59, 130, 246, ${alpha})`;
                        ctx.lineWidth = 1;
                        ctx.stroke();
                    }
                }
            }
            
            requestAnimationFrame(animate);
        }
        
        animate();
    }
    
    // 2. Stats Counters Animation
    const statsData = [
        { id: 'stat-detected', target: 1482, format: (v) => Math.floor(v).toLocaleString() },
        { id: 'stat-safe', target: 98304, format: (v) => Math.floor(v).toLocaleString() },
        { id: 'stat-accuracy', target: 99.4, format: (v) => v.toFixed(1) + '%' },
        { id: 'stat-far', target: 0.12, format: (v) => v.toFixed(2) + '%' }
    ];
    
    const runCounters = () => {
        statsData.forEach(stat => {
            const el = document.getElementById(stat.id);
            if (!el) return;
            
            let current = 0;
            const duration = 1500; // ms
            const interval = 16; // ~60fps
            const step = (stat.target / duration) * interval;
            
            const timer = setInterval(() => {
                current += step;
                if (current >= stat.target) {
                    current = stat.target;
                    clearInterval(timer);
                }
                el.innerText = stat.format(current);
            }, interval);
        });
    };
    
    // Intersection Observer to trigger when counters are in view
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                runCounters();
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.2 });
    
    const statsSection = document.getElementById('stats');
    if (statsSection) {
        observer.observe(statsSection);
    } else {
        // Fallback
        runCounters();
    }
});
