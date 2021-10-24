var currentTab = 'main';
var tabs = [
  ['main', 'flex'],
  ['ptree', 'block', initPtreeStats],
  ['certificates', 'block', initCertificatesStats],
  ['userattributes', 'block', initUserattributesStats],
  ['pubkey', 'block', initPubkeyStats]
];

function switchTab(ev, el){
  if (el == currentTab){
    //deactivate current tab
    document.getElementsByClassName(currentTab)[0].style.display = 'none';
    currentTab = '';
    return;
  }
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
  var elem = document.getElementById(id);
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
        data: values
    }],
    labels: range(0, 51, 10),
  };
  //const options = {
  //    legend: {
  //      display: false
  //    },
  //    scales: {
  //        x: {
  //          ticks: {
  //            display: false,
  //          }
  //          //gridLines: {
  //          //   offsetGridLines: true
  //          //},
  //            //max: 10,
  //            //grid: {
  //            //  offset: true
  //            //}
  //        }
  //    }
  //};
  const options = {
    responsive: true,
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
            var x = tickDistance * 0.12 + tickDistance * index;
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
        data: values,
    }],
    labels: [...values.keys()],
  };
  const options = {
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

function makeCertificateChart1(values){
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
          //maxRotation: 40,
          //minRotation: 40,
          color: 'rgba(255,255,255,0)',
          padding: 5,
        }
      }
    }
  }
 
  makeChart('cert-chart-noua', {
    type: 'bar',
    plugins: [{
      afterDraw: chart => {      
        var xAxis = chart.scales['x'];
        var tickDistance = xAxis.width / (xAxis.ticks.length);
        // add 0
        var y = chart.height - 10; // -10 padding
        chart.ctx.save();        
        chart.ctx.translate(chart.width-xAxis.width-10, y);
        chart.ctx.rotate(-0.25*Math.PI);
        chart.ctx.fillText("0", 0, 0);
        chart.ctx.restore();
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
        data: values["certificates_without_ua"],
      }],
      labels: values["ticks"].concat(String([values["maxsize_noua"]])),
    },
    options: options
  });

  makeChart('cert-chart-ua', {
    type: 'bar',
    plugins: [{
      afterDraw: chart => {      
        var xAxis = chart.scales['x'];
        var tickDistance = xAxis.width / (xAxis.ticks.length);
        // add 0
        var y = chart.height - 10; // -10 padding
        chart.ctx.save();        
        chart.ctx.translate(chart.width-xAxis.width-10, y);
        chart.ctx.rotate(-0.25*Math.PI);
        chart.ctx.fillText("0", 0, 0);
        chart.ctx.restore();
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
        data: values["certificates_with_ua"],
      }],
      labels: values["ticks"].concat(String([values["maxsize_ua"]])),
    },
    options: options
  });


}
function makeCertificateChart2(values){
  const data = {
    datasets: [{
      data: values["year"],
    }],
    labels: values["ticks"].concat([String(values["maxyear"])]),
  };
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
          //maxRotation: 40,
          //minRotation: 40,
          color: 'rgba(255,255,255,0)',
          padding: 5,
        }
      }
    }
  }
 
  makeChart('cert-year', {
    type: 'bar',
    plugins: [{
      afterDraw: chart => {      
        var xAxis = chart.scales['x'];
        var tickDistance = xAxis.width / (xAxis.ticks.length);
        // add 0
        var y = chart.height - 10; // -10 padding
        chart.ctx.save();        
        chart.ctx.translate(chart.width-xAxis.width-10, y);
        chart.ctx.rotate(-0.25*Math.PI);
        chart.ctx.fillText("<1995", 0, 0);
        chart.ctx.restore();
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
    data: data,
    options: options
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
          //maxRotation: 40,
          //minRotation: 40,
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
        chart.ctx.save();        
        chart.ctx.translate(chart.width-xAxis.width-10, y);
        chart.ctx.rotate(-0.25*Math.PI);
        chart.ctx.fillText("0", 0, 0);
        chart.ctx.restore();
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
      }],
      labels: values["ticks"].concat([String(values["maxsize_image"])]),
    },
    options: options
  });
  makeChart('userattributes-chart-other', {
    type: 'bar',
    plugins: [{
      afterDraw: chart => {      
        var xAxis = chart.scales['x'];
        var tickDistance = xAxis.width / (xAxis.ticks.length);
        // add 0
        var y = chart.height - 10; // -10 padding
        chart.ctx.save();        
        chart.ctx.translate(chart.width-xAxis.width-10, y);
        chart.ctx.rotate(-0.25*Math.PI);
        chart.ctx.fillText("0", 0, 0);
        chart.ctx.restore();
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
      }],
      labels: values["ticks"].concat([String(values["maxsize_other"])]),
    },
    options: options
  });

  makeChart('userattributes-pie', {
    type: 'pie',
    data: {
      labels: [
        'None',
        'Image',
        'Other'
      ],
      datasets: [{
        label: 'My First Dataset',
        data: [300, values["images"], values["others"]],
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
    grey: 'rgb(201, 203, 207)'
};

const NAMED_COLORS = [
    CHART_COLORS.red,
    CHART_COLORS.orange,
    CHART_COLORS.yellow,
    CHART_COLORS.green,
    CHART_COLORS.cyan,
    CHART_COLORS.blue,
    CHART_COLORS.purple,
    CHART_COLORS.grey,
];

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
    let basic_values = rpc.get_stats("basic_ptree_stats");
    addRows("ptree-table", basic_values);
    let num_elements = rpc.get_stats("num_elements_ptree_stats");
    makePtreeChart1(num_elements);
    let node_values = rpc.get_stats("node_level_ptree_stats");
    makePtreeChart2(node_values);
    ptreeInitialized = true;
}

var certificatesInitialized = false;
function initCertificatesStats(){
  if (certificatesInitialized) return;
  let certificates_size = rpc.get_stats("certificates_size");
  makeCertificateChart1(certificates_size);
  let certificates_year = rpc.get_stats("certificates_year");
  makeCertificateChart2(certificates_year);
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
  pubkeyInitialized = true;
}

var rpc;
function main() {
    rpc = new JsonRPC('/pks/numbers/rpc', ['get_stats']); 
}
