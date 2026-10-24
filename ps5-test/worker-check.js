self.onmessage = function (event) {
  self.postMessage({
    status: "OK",
    received: event.data,
    workerUserAgent: navigator.userAgent
  });
};
