// Simula un uso intensivo de la CPU durante un período determinado utilizando un Web Worker.
export const simulateCPUStress = (durationInMs) => {
  // Comprobamos si el navegador soporta Web Workers.
  if (window.Worker) {
    const worker = new Worker('/cpu-worker.js');
    worker.postMessage('start'); // Le enviamos un mensaje para que comience.

    setTimeout(() => {
      worker.terminate();
    }, durationInMs);
  } else {
    // Mensaje por si el navegador es muy antiguo.
    
  }
};

// Simula un consumo elevado de memoria RAM durante un período.
export const simulateMemoryStress = (sizeInMB, durationInMs) => {
  const memoryHog = new Array(sizeInMB * 1024 * 256).fill(Math.random());

  setTimeout(() => {
  }, durationInMs);
};
