async function helloWorld(name) {
    const text = `Hello ${name}!`;
    if (text === `Hello ${name}!`) {
        {
            console.log(`Browser says "${text}"`);
        }
    }
    else {
        console.log('This is not going to be printed');
    }
    return text;
}

var helloWorld$1 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    helloWorld: helloWorld
});

async function sayHello() {
    const helloWorld = (await Promise.resolve().then(function () { return helloWorld$1; })).helloWorld;
    await helloWorld('hello');
}

export { sayHello as default, helloWorld };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2hlbGxvLXdvcmxkLnRzIiwiLi4vLi4vc3JjL3RzL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFXTyxlQUFlLFVBQVUsQ0FBRSxJQUFZLEVBQUE7QUFDNUMsSUFBQSxNQUFNLElBQUksR0FBRyxDQUFTLE1BQUEsRUFBQSxJQUFJLEdBQUcsQ0FBQTtBQUM3QixJQUFBLElBQUksSUFBSSxLQUFLLENBQVMsTUFBQSxFQUFBLElBQUksR0FBRyxFQUFFO0FBQzdCLFFBQWdCO0FBQ2QsWUFBQSxPQUFPLENBQUMsR0FBRyxDQUFDLGlCQUFpQixJQUFJLENBQUEsQ0FBQSxDQUFHLENBQUMsQ0FBQTtBQUN0QyxTQUlBO0FBQ0YsS0FBQTtBQUFNLFNBQUE7QUFDTCxRQUFBLE9BQU8sQ0FBQyxHQUFHLENBQUMsaUNBQWlDLENBQUMsQ0FBQTtBQUMvQyxLQUFBO0FBQ0QsSUFBQSxPQUFPLElBQUksQ0FBQTtBQUNiOzs7Ozs7O0FDZmUsZUFBZSxRQUFRLEdBQUE7SUFDcEMsTUFBTSxVQUFVLEdBQUcsQ0FBQyxNQUFNLDREQUF1QixFQUFFLFVBQVUsQ0FBQTtBQUM3RCxJQUFBLE1BQU0sVUFBVSxDQUFDLE9BQU8sQ0FBQyxDQUFBO0FBQzNCOzs7OyJ9
