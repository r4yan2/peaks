var currentTab = 'main';
var tabs = [
  ['main', 'flex'],
  ['ptree', 'block', initPtreeStats],
  ['certificates', 'block', initCertificatesStats],
  ['userattributes', 'block', initUserattributesStats],
  ['pubkey', 'block', initPubkeyStats],
  ['signature', 'block', initSignatureStats],
  ['userid', 'block', initUseridStats],
];

function switchTab(ev, el){
  currentTabEl = document.getElementsByClassName("buttonActive")[0]
  if (currentTabEl) {
    currentTabEl.classList.remove("buttonActive");
  }
  ev.currentTarget.classList.add("buttonActive");
  tabs.forEach(function(tab){ 
    tabElem = document.getElementsByClassName(tab[0])[0];
    tabElem.style.display = (tab[0] === el ? tab[1] : 'none');
    if (tab[0] === el && tab.length === 3){
        tab[2]();
    }
  });
  currentTab = el;
}

var charts = {};

function makeChart(id, chartData, retry=10){
  var elem = document.getElementsByName(id)[0];
  if (!elem){
    if (retry > 0){
        setTimeout("makeChart(${id}, ${chartData}, ${retry-1})", 150);
    } else {
        console.log("Could not load ${id} graph!");
    }
    return;
  }
  charts[id] = new Chart(elem.getContext('2d'), chartData);
}

function makePtreeChart1(values){
  // num elements buckets
  const data = {
    datasets: [{
        data: values["num_elements_ptree_stats"],
        label: 'Elements',
        backgroundColor: NAMED_COLORS[0],
    }],
    labels: range(0, 51, 10),
  };
  const options = {
    responsive: true,
    plugins: {
      title: {
        display: true,
        text: 'Elements per leaf node'
      },
    },
    legend: {
      display: false
    },   
    scales: {
      x: {
        gridLines: {
          offsetGridLines: true
        },
        ticks: {
          color: 'rgba(255,255,255,0)',
        }
      }
    }
  }
 
  makeChart('ptree-chart1', {
    type: 'bar',
    plugins: [{
      afterDraw: chart => {      
        var xAxis = chart.scales['x'];
        var tickDistance = xAxis.width / (xAxis.ticks.length);
        xAxis.ticks.forEach((value, index) => {
            var x = tickDistance * 0.20 + tickDistance * index;
            var y = chart.height - 10;
            chart.ctx.save();        
            chart.ctx.fillText(value.label, x, y);
            chart.ctx.restore();
        });
      }
    }],
    data: data,
    options: options
  });
}

function makePtreeChart2(values){
  // nodes per level
  const data = {
    datasets: [{
        data: values["node_level_ptree_stats"],
        label: 'Nodes per level',
        backgroundColor: NAMED_COLORS[1],
    }],
    labels: range(0, values["node_level_ptree_stats"].length, 1),
  };
  const options = {
       plugins: {
         title: {
           display: true,
           text: 'Node number distribution per level'
         },
       },
        xAxes: {
            ticks: {
                max: 10,
            }
        },
        tension: 0.1
    };
  makeChart('ptree-chart2',{
        type: 'line',
        data: data,
        options: options,
  });
}

function makeCertificateChart(values){

  const plugins = [{
      afterDraw: chart => {      
        var xAxis = chart.scales['x'];
        var tickDistance = xAxis.width / (xAxis.ticks.length);
        var y = chart.height - 30;
        xAxis.ticks.forEach((value, index) => {
            var x = xAxis.left + tickDistance * index;
            chart.ctx.save();        
            chart.ctx.translate(x, y);
            chart.ctx.rotate(-0.25*Math.PI);
            chart.ctx.fillText(String(value.label), 0, 0);
            chart.ctx.restore();
        });      
      }
    }];
 
  makeChart('cert-chart-noua', {
    type: 'bar',
    plugins: plugins,
    data: {
      datasets: [{
        data: values["size"]["certificates_without_ua"],
        label: "Certificates size",
        backgroundColor: NAMED_COLORS[0],
      }],
      labels: values["size"]["ticks"].concat(String([values["size"]["maxsize_noua"]])),
    },
    options: {
    responsive: true,
    legend: {
      display: false
    },   
    title: {
      display: true,
      text: 'Certificate (without user attributes) size divided in bins'
    },
    scales: {
      x: {
        title: {
          text: "KB",
          display: true,
        },
        ticks: {
          autoSkip: false,
          color: 'rgba(255,255,255,0)',
        }
      }
    }
  }

  });
  makeChart('cert-chart-ua', {
    type: 'bar',
    plugins: plugins,
    data: {
      datasets: [{
        data: values["size"]["certificates_with_ua"],
        label: "Certificates size",
        backgroundColor: NAMED_COLORS[1],
      }],
      labels: values["size"]["ticks"].concat(String([values["size"]["maxsize_ua"]])),
    },
    options: {
      responsive: true,
      legend: {
        display: false
      },   
      title: {
        display: true,
        text: 'Certificate (with user attributes) size divided in bins'
      },
      scales: {
        x: {
          title: {
            text: "KB",
            display: true,
          },
          ticks: {
            autoSkip: false,
            color: 'rgba(255,255,255,0)',
          }
        }
      }
  }

  });

  makeChart('cert-year', {
    type: 'bar',
    data: {
      datasets: [{
        data: values["year"]["value"],
        label: "certificates",
        backgroundColor: NAMED_COLORS[2],
      }],
      labels: values["year"]["tick"],
    },
    options: {
      responsive: true,
      legend: {
        display: false
      },   
    }
  });
}

function makeUserattributesChart1(values){
  const options = {
    layout: {
      padding: 10,
    },
    responsive: true,
    legend: {
      display: false
    },   
    scales: {
      x: {
        ticks: {
          //autoSkip: false,
          color: 'rgba(255,255,255,0)',
          padding: 5,
        }
      }
    }
  }
  makeChart('userattributes-chart-image', {
    type: 'bar',
    plugins: [{
      afterDraw: chart => {      
        var xAxis = chart.scales['x'];
        var tickDistance = xAxis.width / (xAxis.ticks.length);
        // add 0
        var y = chart.height - 10; // -10 padding
        xAxis.ticks.forEach((value, index) => {
            var x = tickDistance * 1.5 + tickDistance * index;
            chart.ctx.save();        
            chart.ctx.translate(x, y);
            chart.ctx.rotate(-0.25*Math.PI);
            chart.ctx.fillText(String(value.label)+"KB", 0, 0);
            chart.ctx.restore();
        });      
      }
    }],
    data: {
      datasets: [{
        data: values["image"]["size"],
        backgroundColor: NAMED_COLORS[0],
      }],
      labels: values["ticks"].concat([String(values["maxsize_image"])]),
    },
    options: Object.assign({}, options, {plugins: {title: {display: true, text: "Image attribute size divided in bins"}}})
  });
  makeChart('userattributes-chart-other', {
    type: 'bar',
    plugins: [{
      afterDraw: chart => {      
        var xAxis = chart.scales['x'];
        var tickDistance = xAxis.width / (xAxis.ticks.length);
        // add 0
        var y = chart.height - 10; // -10 padding
        xAxis.ticks.forEach((value, index) => {
            var x = tickDistance * 1.5 + tickDistance * index;
            chart.ctx.save();        
            chart.ctx.translate(x, y);
            chart.ctx.rotate(-0.25*Math.PI);
            chart.ctx.fillText(String(value.label)+"KB", 0, 0);
            chart.ctx.restore();
        });      
      }
    }],
    data: {
      datasets: [{
        data: values["other"]["size"],
        backgroundColor: NAMED_COLORS[1],
      }],
      labels: values["ticks"].concat([String(values["maxsize_other"])]),
    },
    options: Object.assign({}, options, {plugins: {title: {display: true, text: "Other attribute size divided in bins"}}})
  });

  makeChart('userattributes-pie', {
    type: 'pie',
    data: {
      labels: [
        'No attribute',
        'Image',
        'Other'
      ],
      datasets: [{
        data: [values["none"], values["images"], values["others"]],
        backgroundColor: [
          'rgb(255, 99, 132)',
          'rgb(54, 162, 235)',
          'rgb(255, 205, 86)'
        ],
        hoverOffset: 4
      }]
    }
  });
}

const CHART_COLORS = {
    red: 'rgb(255, 99, 132)',
    orange: 'rgb(255, 159, 64)',
    yellow: 'rgb(255, 205, 86)',
    green: 'rgb(75, 192, 192)',
    cyan: 'rgb(66, 215, 245)',
    blue: 'rgb(54, 162, 235)',
    purple: 'rgb(153, 102, 255)',
    grey: 'rgb(50, 50, 50)'
};

const NAMED_COLORS = [
    CHART_COLORS.red,
    CHART_COLORS.orange,
    CHART_COLORS.yellow,
    CHART_COLORS.green,
    CHART_COLORS.cyan,
    CHART_COLORS.blue,
    CHART_COLORS.purple,
];

function color(i){
  return NAMED_COLORS[i%NAMED_COLORS.length];
}

function makePubkeyChart1(values){

  const algorithms = values["generic"]["algorithms_map"];
  const years = values["generic"]["years"];
  const rsa_data = [].concat(...[1,2,3].map(r => values["generic"][algorithms[r]]));
  const dsa_data = [].concat(...[17].map(r => values["generic"][algorithms[r]]));
  const elgamal_data = [].concat(...[16].map(r => values["generic"][algorithms[r]]));
  const ec_data = [].concat(...[18,19].map(r => values["generic"][algorithms[r]]));
  let data = {
    labels: years,
    datasets: [
      {
        label: 'RSA',
        data: rsa_data,
        backgroundColor: CHART_COLORS.orange,
      }, {
        label: 'DSA',
        data: dsa_data,
        backgroundColor: CHART_COLORS.red,
      }, {
        label: 'Elgamal',
        data: elgamal_data,
        backgroundColor: CHART_COLORS.blue,
      }, {
        label: 'Elliptic Curve',
        data: ec_data,
        backgroundColor: CHART_COLORS.green,
      },
    ]
  };

  makeChart('pubkey-stacked', {
    type: 'bar',
    data: data,
    options: {
      plugins: {
        title: {
          display: true,
          text: 'Distribution of algorithm per year'
        },
      },
      responsive: true,
      scales: {
        x: {
          stacked: true,
        },
        y: {
          stacked: true
        }
      }
    }
  });

  makeChart('pubkey-pie', {
    type: 'pie',
    options: {
      responsive: true,
    },
    data: {
      labels: [
        'RSA',
        'DSA',
        'Elgamal',
        'Elliptic Curve',
      ],
      datasets: [{
        label: 'Key distribution',
        data: [values["generic"]["rsa_count"], values["generic"]["dsa_count"], values["generic"]["elgamal_count"], values["generic"]["elliptic_count"]],
        backgroundColor: [
          'rgb(255, 99, 132)',
          'rgb(54, 162, 235)',
          'rgb(255, 205, 86)',
          'rgb(20, 20, 200)',
        ],
        hoverOffset: 4
      }]
    }
  });

  data_label = ["up to 512", "512 to 1024", "1024 to 2048", "2048 to 4096", "more than 4096"];
  data = {
    labels: years,
    datasets: data_label.map((lab, idx) => {return {
      label: lab,
      data: values["rsa"]["n_sizes"].map(v => v[idx]),
      backgroundColor: NAMED_COLORS[idx],
    }})
  };

  makeChart('pubkey-rsa', {
    type: 'bar',
    data: data,
    options: {
      plugins: {
        title: {
          display: true,
          text: 'Distribution of n per year'
        },
      },
      responsive: true,
      scales: {
        x: {
          stacked: true,
        },
        y: {
          stacked: true
        }
      }
    }
  });

  data_label = ["up to 1024", "1024 to 2048", "2048 to 3072", "over 3072"];
  data = {
    labels: years,
    datasets: data_label.map((lab, idx) => {return {
      label: lab,
      data: values["elgamal"]["p_sizes"].map(v => v[idx]),
      backgroundColor: NAMED_COLORS[idx],
    }})
  };

  makeChart('pubkey-elgamal', {
    type: 'bar',
    data: data,
    options: {
      plugins: {
        title: {
          display: true,
          text: 'Distribution of n per year'
        },
      },
      responsive: true,
      scales: {
        x: {
          stacked: true,
        },
        y: {
          stacked: true
        }
      }
    }
  });

  data_label_p = ["up to 1024", "1024 to 2048", "2048 to 3072", "over 3072"];
  data_label_q = ["up to 160", "160 to 224", "224 to 256", "over 256"];
  data = {
    labels: years,
    datasets: data_label_p.map((lab, idx) => {return {
      label: lab,
      data: values["dsa"]["p_sizes"].map(v => v[idx]),
      backgroundColor: NAMED_COLORS[idx],
      stack: 'p',
    }}).concat(
      data_label_q.map((lab, idx) => {return {
      label: lab,
      data: values["dsa"]["q_sizes"].map(v => v[idx]),
      backgroundColor: NAMED_COLORS[idx+4],
      stack: 'q',
      }})
    )
  };

  makeChart('pubkey-dsa', {
    type: 'bar',
    data: data,
    options: {
      plugins: {
        title: {
          display: true,
          text: 'Chart.js Bar Chart - Stacked'
        },
      },
      responsive: true,
      interaction: {
        intersect: false,
      },
      scales: {
        x: {
          stacked: true,
        },
        y: {
          stacked: true
        }
      }
    }
   });

  makeChart('pubkey-ec', {
    type: 'bar',
    data: {
      labels: years,
      datasets: [
        {
          labels: years,
          data: values["elliptic"]["sizes"],
          backgroundColor: NAMED_COLORS[0]
        }
      ]
    },
    options: {
      plugins: {
        title: {
          display: true,
          text: 'Chart.js Bar Chart - Stacked'
        },
      },
      responsive: true,
    }
   });

  makeChart('pubkey-counter', {
    type: 'line',
    data: {
      labels: years,
      datasets: [
        {
          labels: years,
          data: values["generic"]["counter"],
          borderColor: NAMED_COLORS[0],
          fill: false,
          cubicInterpolationMode: 'monotone',
          tension: 0.3,
        }
      ]
    },
    options: {
      plugins: {
        title: {
          display: true,
          text: 'Chart.js Bar Chart - Stacked'
        },
      },
      interaction: {
              intersect: false,
            },
      responsive: true,
    }
   });

}

function makeUseridChart1(values){

  addRows("userid-table", values["generic"]);
  makeChart('userid-domain-horizontal', {
    type: 'bar',
    data: {
      labels: values["domain"]["label"],
      datasets: [{
        data: values["domain"]["value"],
        backgroundColor: CHART_COLORS.blue,
      }]
    },
    options: {
      indexAxis: 'y',
      // Elements options apply to all of the options unless overridden in a dataset
      // In this case, we are setting the border of each horizontal bar to be 2px wide
      elements: {
        bar: {
          borderWidth: 2,
        }
      },
      responsive: true,
      plugins: {
        legend: {
          position: 'right',
        },
        title: {
          display: true,
          text: 'Top 10 domain for mail in userID'
        }
      }
    }
  });
  makeChart('userid-size-chart', {
    type: 'bar',
    plugins: [{
      afterDraw: chart => {      
        var xAxis = chart.scales['x'];
        var tickDistance = xAxis.width / (xAxis.ticks.length);
        // add 0
        var y = chart.height - 10; // -10 padding
        xAxis.ticks.forEach((value, index) => {
            var x = tickDistance * 1.5 + tickDistance * index;
            chart.ctx.save();        
            chart.ctx.translate(x, y);
            chart.ctx.rotate(-0.25*Math.PI);
            chart.ctx.fillText(value.label, 0, 0);
            chart.ctx.restore();
        });      
      }
    }],
    data: {
      datasets: [{
        data: values["size"]["value"],
        backgroundColor: NAMED_COLORS[2],
      }],
      labels: values["size"]["label"],
    },
    options: {
      plugins: {
        title: {
          display: true,
          text: "UID length divided in bins",
        }
      },
      layout: {
        padding: 10,
      },
      responsive: true,
      legend: {
        display: false
      },   
      scales: {
        x: {
          ticks: {
            color: 'rgba(255,255,255,0)',
            padding: 5,
          }
        }
      }
  }
 
  });


}

function makeSignatureChart1(values){

  addRows("signature-table", values["generic"]);
  const algorithms = values["static"]["algorithms_map"];
  const years = values["static"]["years"];
  const rsa_data = values["year"][algorithms[1]];
  const rsa_sign_data = values["year"][algorithms[3]];
  const dsa_data = values["year"][algorithms[17]];
  const elgamal_data = values["year"][algorithms[16]];
  const ec_data = values["year"][algorithms[18]].map((val, idx)=>val+values["year"][algorithms[19]][idx]);
  let data = {
    labels: years,
    datasets: [
      {
        label: 'RSA',
        data: rsa_data,
        backgroundColor: CHART_COLORS.orange,
      }, {
        label: 'RSA (Sign Only)',
        data: rsa_sign_data,
        backgroundColor: CHART_COLORS.purple,
      }, {
        label: 'DSA',
        data: dsa_data,
        backgroundColor: CHART_COLORS.red,
      }, {
        label: 'Elgamal',
        data: elgamal_data,
        backgroundColor: CHART_COLORS.blue,
      }, {
        label: 'Elliptic Curve',
        data: ec_data,
        backgroundColor: CHART_COLORS.green,
      },
    ]
  };

  makeChart('signature-alg-stacked', {
    type: 'bar',
    data: data,
    options: {
      plugins: {
        title: {
          display: true,
          text: 'Distribution of algorithm per year'
        },
      },
      responsive: true,
      scales: {
        x: {
          stacked: true,
        },
        y: {
          stacked: true
        }
      }
    }
  });

  data = {
    labels: years,
    datasets: ["signatures valid", "signatures expired", "signatures revocation","self signatures valid", "self signatures expired", "self signatures revocation"].map((val, idx)=>{ return{
      label: val,
      data: values["year"][val],
      backgroundColor: color(idx),
    }}),
  };

  makeChart('signature-stacked', {
    type: 'bar',
    data: data,
    options: {
      plugins: {
        title: {
          display: true,
          text: 'Distribution of algorithm per year'
        },
      },
      responsive: true,
      scales: {
        x: {
          stacked: true,
        },
        y: {
          stacked: true
        }
      }
    }
  });

  data = {
    labels: years,
    datasets: ["signatures", "self signatures"].map((val, idx)=>{ return {
      label: val,
      data: values["year"][val],
      backgroundColor: color(idx),
    }}),
  };

  makeChart('signature-simple-stacked', {
    type: 'bar',
    data: data,
    options: {
      plugins: {
        title: {
          display: true,
          text: 'Distribution of algorithm per year'
        },
      },
      responsive: true,
      scales: {
        x: {
          stacked: true,
        },
        y: {
          stacked: true
        }
      }
    }
  });



  makeChart('signature-pie', {
    type: 'pie',
    data: {
      labels: [
        'Signature Valid',
        'Signature Expired',
        'Self Signature Valid',
        'Self Signature Expired',
      ],
      datasets: [{
        label: 'My First Dataset',
        data: [
          values["generic"]["signatures valid"],
          values["generic"]["signatures expired"],
          values["generic"]["self signatures valid"],
          values["generic"]["self signatures expired"],
        ],
        backgroundColor: range(0,7,1).map(n=>color(n)),
        hoverOffset: 4
      }]
    }
  });


}

function makePubkeyVulnerabilityChart1(values){

  //const algorithms = values["generic"]["algorithms_map"];
  const algorithms = ["rsa", "elgamal", "dsa", "ec"];
  const vulnerabilities = values["vulnerability"]["vulnerability_map"];
  const years = values["generic"]["years"];
  algorithms.map(alg => {
    const healthy_data = values["vulnerability"]['healthy_'+alg];
    const unhealhy_data = values["vulnerability"]['unhealthy_'+alg];
    const data = {
      labels: years,
      datasets: [
        {
          label: 'Healthy',
          data: healthy_data,
          backgroundColor: CHART_COLORS.blue,
        }, {
          label: 'Unhealthy',
          data: healthy_data,
          backgroundColor: CHART_COLORS.red,
        },
      ]
    };

    makeChart('pubkey-healthy-'+alg, {
      type: 'bar',
      data: data,
      options: {
        plugins: {
          title: {
            display: true,
            text: 'Distribution of algorithm per year'
          },
        },
        responsive: true,
        scales: {
          x: {
            stacked: true,
          },
          y: {
            stacked: true
          }
        }
      }
    });
  })

  algorithms.map(alg => {
    let data = {
      labels: years,
      datasets: Object.keys(vulnerabilities).map((lab, idx) => {return {
        label: lab,
        data: values["vulnerability"][alg][lab],
        backgroundColor: color(idx),
      }}).filter(obj => (obj.data.reduce((acc, e) => {return acc + e;}, 0)) > 0)
    };
    makeChart("pubkey-vulnerability-"+alg, {
      type: 'bar',
      data: data,
      options: {
        plugins: {
          title: {
            display: true,
            text: 'Distribution of algorithm per year'
          },
        },
        responsive: true,
        scales: {
          x: {
            stacked: true,
          },
          y: {
            stacked: true
          }
        }
      }
    });


  });

}

function fetchReport(){
    fetch('get_report')
   .then(res => res.json())
   .then((out) => {
     makeMemoryGraph(out);
     makeSwapGraph(out);
     makeLoadGraph(out);
   })
   .catch(err => { console.log(err) });
}


function range(start, stop, step) {
    if (typeof stop == 'undefined') {
        // one param defined
        stop = start;
        start = 0;
    }

    if (typeof step == 'undefined') {
        step = 1;
    }

    if ((step > 0 && start >= stop) || (step < 0 && start <= stop)) {
        return [];
    }

    var result = [];
    for (var i = start; step > 0 ? i < stop : i > stop; i += step) {
        result.push(i);
    }

    return result;
};

//var xhr = new XMLHttpRequest();  
//xhr.open("post", '/pks/numbers');  
// Required by JSON-RPC over HTTP  
//xhr.setRequestHeader("Content-Type","application/json");  
//var request = '{"method":"ptree_stats"}'; 
//
//xhr.onreadystatechange = function() {  
//   if (xhr.readyState === 4) {  
//    var res;  
//    if(xhr.status === 200) {  
//        // Don't call eval in real code use some parser  
//        var result = JSON.parse(xhr.responseText);  
//        console.log(result);  
//    }  
//    else {  
//        res = 'Invalid Status ' + xhr.status;  
//    }  
//} 
//}  
//xhr.send(request);  
function addRows(table, content) {
  let tableRef = document.getElementById(table);
  for (var key in content) {
      let newRow = tableRef.insertRow(-1);
      let keyCell = newRow.insertCell(0);
      let valueCell = newRow.insertCell(1);
      let keyText = document.createTextNode(key);
      let valueText = document.createTextNode(content[key]);
      keyCell.appendChild(keyText);
      valueCell.appendChild(valueText);
  }
}

var ptreeInitialized = false;
function initPtreeStats(){
    if (ptreeInitialized) return;
    let values = rpc.get_stats("ptree");
    addRows("ptree-table", values["generic"]);
    makePtreeChart1(values);
    makePtreeChart2(values);
    ptreeInitialized = true;
}

var certificatesInitialized = false;
function initCertificatesStats(){
  if (certificatesInitialized) return;
  let values = rpc.get_stats("certificates");
  makeCertificateChart(values);
  certificatesInitialized = true;
}

var userattributesInitialized = false;
function initUserattributesStats(){
  if (userattributesInitialized) return;
  let value = rpc.get_stats("userattributes");
  makeUserattributesChart1(value);
  userattributesInitialized = true;
}

var pubkeyInitialized = false;
function initPubkeyStats(){
  if (pubkeyInitialized) return;
  let value = rpc.get_stats("pubkey");
  makePubkeyChart1(value);
  makePubkeyVulnerabilityChart1(value);
  pubkeyInitialized = true;
}

var signatureInitialized = false;
function initSignatureStats(){
  if (signatureInitialized) return;
  let value = rpc.get_stats("signature");
  makeSignatureChart1(value);
  signatureInitialized = true;
}

var useridInitialized = false;
function initUseridStats(){
  if (useridInitialized) return;
  let value = rpc.get_stats("userid");
  makeUseridChart1(value);
  useridInitialized = true;
}
var rpc;
function main() {
    rpc = new JsonRPC('/pks/numbers/rpc', ['get_stats']); 
}
