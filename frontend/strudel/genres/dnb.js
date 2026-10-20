// Drum & Bass: ~170–175 BPM, Breakbeats, Sub-Bass. Varianten nach gängigen Subgenres.
export default {
  key: "dnb", name: "Drum & Bass", color: "#199e70",
  tracks: [
    { key: "kick", label: "Kick", code: 's("bd ~ ~ ~ ~ ~ bd ~ ~ ~ bd ~ ~ ~ ~ ~").bank("{B}").gain(1.1)' },
    { key: "snare", label: "Snare", code: 's("~ ~ ~ ~ sd ~ ~ ~ ~ ~ ~ ~ sd ~ ~ ~").bank("{B}").gain(.9)' },
    { key: "ghost", label: "Ghost-Snares", code: 's("~ ~ ~ ~ ~ ~ ~ sd ~ sd ~ ~ ~ ~ ~ sd").bank("{B}").gain(.25)' },
    { key: "hats", label: "Hi-Hats", code: 's("hh*8").bank("{B}").gain("[.5 .3]*4")' },
    { key: "ride", label: "Ride", code: 's("[~ rd]*4").bank("{B}").gain(.2)' },
    { key: "break", label: "Amen-Break", code: 's("amencutup").n("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15").gain(.55)' },
    { key: "perc", label: "Percussion", code: 's("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [~ rim] ~").bank("{B}").gain(.5)' },
    { key: "sub", label: "Sub-Bass", code: 'n("<0 0 3 -2>").scale("{K}1:{S}").s("sine").sustain(.9).gain(1)' },
    { key: "reese", label: "Reese-Bass", code: 'n("<0 0 3 -2>").scale("{K}1:{S}").s("supersaw").lpf(sine.range(200,900).fast(2)).lpq(8).sustain(.8).gain(.45)' },
    { key: "pad", label: "Pad", code: 'n("<[0,2,4] [3,5,7] [-2,0,2] [1,3,5]>").scale("{K}3:{S}").s("supersaw").attack(.3).release(.8).lpf(1600).gain(.2).slow(2)' },
    { key: "lead", label: "Lead", code: 'n("~ 7 ~ 4 ~ ~ 2 ~").scale("{K}4:{S}").s("sine").decay(.3).sustain(0).gain(.35).delay(.45)' },
    { key: "atmo", label: "Atmosphäre", code: 'n("<[0,4] [-2,2]>").scale("{K}2:{S}").s("sawtooth").attack(1).release(2).lpf(500).gain(.18).slow(2)' },
  ],
  variants: [
    { key: "dancefloor", name: "Dancefloor", bpm: 174, bank: "AkaiMPC60", scale: "minor", key0: "E",
      desc: "Klassischer Two-Step mit Reese-Bass", on: ["kick", "snare", "hats", "reese", "sub"], tracks: {} },
    { key: "liquid", name: "Liquid", bpm: 174, bank: "AkaiMPC60", scale: "minor", key0: "F",
      desc: "Sanft, Piano und Flächen, souliger Bass", on: ["kick", "snare", "ghost", "ride", "sub", "pad", "lead"],
      tracks: {
        pad: 'n("<[0,2,4,6] [-2,0,2,4] [-3,-1,1,3] [1,3,5,7]>").scale("{K}3:{S}").struct("x ~ ~ x ~ ~ x ~").s("piano").gain(.45).room(.5)',
        lead: 'n("~ 4 ~ [6 4] ~ 2 ~ ~").scale("{K}4:{S}").s("triangle").decay(.4).sustain(0).gain(.3).delay(.4).room(.4)',
        sub: 'n("<0 -3 -2 -4>").scale("{K}1:{S}").s("sine").sustain(.9).gain(1)',
      } },
    { key: "neuro", name: "Neurofunk", bpm: 174, bank: "AkaiMPC60", scale: "phrygian", key0: "D",
      desc: "Gefilterter, verzerrter Bass, harte Snare", on: ["kick", "snare", "hats", "reese", "perc"],
      tracks: {
        snare: 's("~ ~ ~ ~ sd ~ ~ ~ ~ ~ ~ ~ sd ~ ~ ~").bank("{B}").gain(1).shape(.3)',
        reese: 'n("0 ~ [0 1] ~ ~ 0 ~ <-1 3>").scale("{K}1:{S}").s("supersaw").lpf(sine.range(150,1800).fast(4)).lpq(12).shape(.5).sustain(.6).gain(.4)',
      } },
    { key: "jungle", name: "Jungle", bpm: 165, bank: "AkaiMPC60", scale: "minor", key0: "A",
      desc: "Zerhackter Amen-Break, tiefer Sub", on: ["break", "sub", "atmo"],
      tracks: {
        break: 's("amencutup").n("0 1 [2 2] 3 4 [5 13] 6 7 8 9 10 [11 11] 12 13 [14 3] 15").gain(.6)',
        sub: 'n("0 ~ ~ ~ ~ ~ 0 ~ <3 -2> ~ ~ ~ ~ ~ ~ ~").scale("{K}1:{S}").s("sine").sustain(.9).gain(1)',
      } },
    { key: "jumpup", name: "Jump-Up", bpm: 175, bank: "AkaiMPC60", scale: "minor", key0: "G",
      desc: "Hüpfender, eingängiger Bass, simpel und laut", on: ["kick", "snare", "hats", "reese"],
      tracks: {
        reese: 'n("0 ~ 0 [7 ~] ~ 0 [~ 5] ~").scale("{K}1:{S}").s("square").lpf(sine.range(300,1500).fast(8)).lpq(10).decay(.2).sustain(.3).gain(.4)',
      } },
    { key: "halftime", name: "Halftime", bpm: 170, bank: "AkaiMPC60", scale: "minor", key0: "C",
      desc: "Halbes Tempo im Beat, Bass rollt weiter", on: ["kick", "snare", "hats", "reese", "atmo"],
      tracks: {
        kick: 's("bd ~ ~ ~ ~ ~ ~ bd ~ ~ ~ ~ ~ ~ ~ ~").bank("{B}").gain(1.1)',
        snare: 's("~ ~ ~ ~ ~ ~ ~ ~ sd ~ ~ ~ ~ ~ ~ ~").bank("{B}").gain(1)',
        hats: 's("[hh hh?]*4").bank("{B}").gain(.35)',
      } },
    { key: "atmos", name: "Atmospheric", bpm: 172, bank: "AkaiMPC60", scale: "dorian", key0: "E",
      desc: "Träumerisch, viel Raum (LTJ Bukem)", on: ["break", "sub", "pad", "atmo", "lead"],
      tracks: {
        break: 's("amencutup").n("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15").gain(.35).lpf(3000)',
        atmo: 'n("<[0,4,7] [-1,3,6]>").scale("{K}2:{S}").s("supersaw").attack(2).release(3).lpf(900).gain(.15).slow(4).room(.7)',
      } },
  ],
};
