export async function renderLottie(el, options) {
    if (!el) return;
    // options: { path, loop, autoplay, speed }
    const anim = lottie.loadAnimation({
        container: el,
        renderer: 'svg',
        loop: options?.loop ?? true,
        autoplay: options?.autoplay ?? true,
        path: options.path
    });
    if (options?.speed) anim.setSpeed(options.speed);

    // visszaadunk egyszerű vezérlő metódusokat
    return {
        play: () => anim.play(),
        pause: () => anim.pause(),
        stop: () => anim.stop(),
        setSpeed: (s) => anim.setSpeed(s),
        setDirection: (d) => anim.setDirection(d), // 1 vagy -1
        goToAndPlay: (f) => anim.goToAndPlay(f, true),
        goToAndStop: (f) => anim.goToAndStop(f, true),
        destroy: () => anim.destroy()
    };
}
