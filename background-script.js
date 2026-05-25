const canvas = document.getElementById("liquid-bg");

canvas.style.position = "fixed";
canvas.style.top = "0";
canvas.style.left = "0";
canvas.style.width = "100%";
canvas.style.height = "100%";
canvas.style.zIndex = "-1";

const liquid = new LiquidEther(canvas, {
  colors: ["#5227FF", "#FF9FFC", "#B19EEF"], // your palette
  speed: 0.8,
  resolution: 1.0
});
