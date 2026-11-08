# Vector PolicyVice icon on a 1024 unit canvas, in the same style and colours as the LogVice icon:
# the three policy lines on the left and a shield with a check where LogVice has its magnifier.
NAVY, CYAN, PINK = '#011133', '#00EEFE', '#FF199A'

def at_least(size, base, table):
    px = table.get(size, 0)
    return max(base, px * 1024.0 / size)

def app(size):
    w = at_least(size, 36, {16: 1.3, 20: 1.4, 24: 1.5, 32: 1.6, 40: 1.8, 48: 1.9, 64: 2.3})
    lines = [(155, 420, 358), (155, 390, 483), (155, 340, 608)] if size > 16 else [(155, 420, 400), (155, 360, 590)]
    shield = 'M 662 262 L 836 324 V 476 C 836 598 758 676 662 722 C 566 676 488 598 488 476 V 324 Z'
    check = 'M 588 492 L 642 546 L 744 442' if size > 20 else 'M 584 494 L 640 550 L 748 440'
    parts = ['<rect x="20" y="20" width="984" height="984" rx="150" fill="%s"/>' % NAVY]
    for x0, x1, y in lines:
        parts.append('<line x1="%g" y1="%g" x2="%g" y2="%g" stroke="%s" stroke-width="%g" stroke-linecap="round"/>' % (x0 + w / 2, y, x1, y, CYAN, w))
    parts.append('<path d="%s" fill="none" stroke="%s" stroke-width="%g" stroke-linejoin="round"/>' % (shield, PINK, w))
    parts.append('<path d="%s" fill="none" stroke="%s" stroke-width="%g" stroke-linecap="round" stroke-linejoin="round"/>' % (check, CYAN, w))
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">' + ''.join(parts) + '</svg>'
