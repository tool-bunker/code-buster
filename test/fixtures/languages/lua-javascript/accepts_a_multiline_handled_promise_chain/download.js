fetch(modelUrl, {
  signal,
})
  .then(handleResponse)
  .catch(handleError);

fetch(otherUrl);
